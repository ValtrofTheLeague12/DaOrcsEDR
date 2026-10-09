#include "pipeline.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <iomanip>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "console.hpp"
#include "logging.hpp"
#include "pipeline_planner.hpp"

namespace pipeline {

// ---------------------------------------------------------------------------
// Phases 4-5: IAT (PE) + MalAPI lookup
// ---------------------------------------------------------------------------
// The MalAPI database is queried with the functions actually imported from
// DLLs (IAT names) instead of heuristic guesses over raw strings.
void run_iat_and_malapi(context& ctx) {
  // -------- Phase 4: IAT (PE) --------
  // Extracted straight onto the context: the MalAPI pass below reads it, the
  // export writes iat/<stem>_iat.json from it when extraction is not in the
  // pipeline, and it is released again at the end when extraction will
  // re-derive the same table.
  phase(ctx, ctx.is_pe, "import table (PE)");
  {
    const auto started = report_clock::now();
    if (ctx.is_pe) {
      if (extractor::extract_iat(ctx.iat_result, ctx.info)) print_iat_report(ctx.iat_result);
      else {
        for (const auto& message : extractor::get_error_messages(ctx.iat_result))
          console::error(message);
      }
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 5: MalAPI lookup over imported functions --------
  phase(ctx, ctx.is_pe, "MalAPI lookup (imported functions)");
  {
    const auto started = report_clock::now();

    if (ctx.api == nullptr || !ctx.api->running()) {
      console::info("local API server not running; skipping MalAPI lookups");
    } else if (ctx.is_pe) {
      constexpr std::size_t kMaxQueries = 500;

      std::set<std::string> seen;
      std::vector<std::string> queue;
      queue.reserve(std::min<std::size_t>(kMaxQueries, ctx.iat_result.entries.size()));

      for (const auto& entry : ctx.iat_result.entries) {
        if (queue.size() >= kMaxQueries) break;
        if (entry.name.empty()) continue;  // ordinal-only import
        if (!looks_like_api_name(entry.name)) continue;
        if (!seen.insert(entry.name).second) continue;
        queue.push_back(entry.name);
      }

      LOG_INFO("malapi: querying {} imported function name(s)", queue.size());
      print_kv("Candidates", std::to_string(queue.size()));

      // Show which imported functions are actually being looked up. Without
      // this the phase reported only a count, so it was impossible to tell
      // what was queried when a hit or a miss mattered.
      if (!queue.empty()) {
        print_section("MalAPI lookup candidates");
        constexpr std::size_t kMaxShown = 60;
        std::size_t shown = 0;
        for (const std::string& name : queue) {
          if (shown >= kMaxShown) break;
          print_bullet(name, console::cyan);
          ++shown;
        }
        if (shown < queue.size()) {
          print_bullet("... and " + std::to_string(queue.size() - shown) +
                       " more candidate(s)", console::grey);
        }
      }

      std::vector<std::string> hits;
      hits.reserve(queue.size());

      for (const std::string& name : queue) {
        const auto hit = query_malapi(*ctx.api, name);
        if (!hit) continue;
        hits.push_back(format_malapi_hit(*hit));
        ctx.malapi_hits.push_back(*hit);   // structured, for the dashboard
      }

      if (hits.empty()) {
        console::info("no MalAPI matches among the imported functions");
      } else {
        print_section("MalAPI matches (" + std::to_string(hits.size()) + ")");
        for (const std::string& line : hits) {
          print_bullet(line, console::red);
        }
      }
    }

    print_duration(elapsed_ms(started));
  }
  // With extraction in the pipeline the export reads the IAT from ctx.full,
  // so drop the copy kept for partial pipelines - this phase used to be the
  // owner of a local result released right here, before the memory-heavy
  // phases.
  if (planner::has(ctx, planner::phase_id::extraction)) {
    extractor::iat_result_t empty{};
    std::swap(ctx.iat_result, empty);
  }
}

// ---------------------------------------------------------------------------
// Phase 6: GOT (ELF / Mach-O)
// ---------------------------------------------------------------------------
void run_got(context& ctx) {
  phase(ctx, ctx.is_elf || ctx.is_macho, "GOT / PLT (ELF, Mach-O)");
  // Kept on the context so a pipeline without the extraction phase can still
  // export it; released again below when extraction re-derives the same table.
  const auto started = report_clock::now();
  if (ctx.is_elf || ctx.is_macho) {
    if (extractor::extract_got(ctx.got_result, ctx.info)) print_got_report(ctx.got_result);
    else {
      for (const auto& message : extractor::get_error_messages(ctx.got_result))
        console::error(message);
    }
  }
  if (planner::has(ctx, planner::phase_id::extraction)) {
    extractor::got_result_t empty{};
    std::swap(ctx.got_result, empty);
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 7: byte histogram
// ---------------------------------------------------------------------------
void run_byte_histogram(context& ctx) {
  phase(ctx, true, "byte histogram");
  const auto started = report_clock::now();
  extractor::byte_histogram_t result{};
  if (extractor::extract_byte_histogram(result, ctx.info)) {
    std::ostringstream entropy_os;
    entropy_os << std::fixed << std::setprecision(4) << result.entropy << " bits/byte";
    print_kv("Entropy", entropy_os.str());
    print_kv("Total bytes", std::to_string(result.total_bytes));
    print_kv("Distinct bytes", std::to_string(result.nonzero_bins) + " / 256");
    {
      char buf[16];
      std::snprintf(buf, sizeof(buf), "0x%02x", result.most_common_byte);
      std::ostringstream os;
      os << buf << "  x" << result.counts[result.most_common_byte];
      print_kv("Most common", os.str());
    }
    print_section("top byte values");
    struct byte_row { std::uint8_t value; std::uint64_t count; double freq; };
    std::vector<byte_row> rows;
    for (std::size_t i = 0; i < 256; ++i) {
      if (result.counts[i] == 0) continue;
      rows.push_back({static_cast<std::uint8_t>(i), result.counts[i], result.frequencies[i]});
    }
    std::sort(rows.begin(), rows.end(),
              [](const byte_row& a, const byte_row& b) { return a.count > b.count; });
    std::size_t shown = 0;
    for (const auto& row : rows) {
      if (shown >= 10) break;
      std::ostringstream os;
      os << "0x" << std::hex << std::setw(2) << std::setfill('0')
         << static_cast<unsigned>(row.value) << std::dec << std::setfill(' ')
         << "  x" << std::setw(8) << row.count
         << "  (" << std::fixed << std::setprecision(3) << row.freq * 100.0 << "%)";
      print_bullet(os.str());
      ++shown;
    }
  } else {
    for (const auto& message : extractor::get_error_messages(result))
      console::error(message);
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 8: packer
// ---------------------------------------------------------------------------
void run_packer(context& ctx) {
  phase(ctx, true, "packer detection");
  const auto started = report_clock::now();
  extractor::packer_detection_t result{};
  if (extractor::detect_if_packed(result, ctx.info)) {
    if (result.packed) {
      print_kv_colored("Verdict", "SUSPICIOUS (packed)", console::red);
      for (const auto& reason : result.reasons) print_bullet(reason, console::red);
    } else {
      print_kv_colored("Verdict", "clean (no packer indicators)", console::green);
    }
  } else {
    for (const auto& message : extractor::get_error_messages(result))
      console::error(message);
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 9: opcodes
// ---------------------------------------------------------------------------
void run_opcodes(context& ctx) {
  phase(ctx, true, "opcode statistics");
  const auto started = report_clock::now();
  extractor::opcode_stats_t result{};
  if (extractor::generate_opcode_stats(result, ctx.info)) {
    print_kv("Architecture", result.architecture);
    print_kv("Instructions", std::to_string(result.total_instructions));
    print_section("top opcode bytes");
    std::size_t top = 0;
    for (std::size_t i = 0; i < 256 && top < 10; ++i) {
      if (result.counts[i] == 0) continue;
      std::ostringstream os;
      os << "0x" << std::hex << std::setw(2) << std::setfill('0') << i
         << std::dec << std::setfill(' ')
         << "  x" << std::setw(6) << result.counts[i]
         << "  (" << std::fixed << std::setprecision(3)
         << result.frequencies[i] * 100.0 << "%)";
      print_bullet(os.str());
      ++top;
    }
  } else {
    for (const auto& message : extractor::get_error_messages(result))
      console::error(message);
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 10: debug symbols
// ---------------------------------------------------------------------------
void run_debug_symbols(context& ctx) {
  phase(ctx, true, "debug symbols");
  const auto started = report_clock::now();
  extractor::debug_symbols_t result{};
  if (extractor::extract_debug_symbols(result, ctx.info)) {
    print_kv("Format",  result.format);
    print_kv("Symbols", std::to_string(result.symbols.size()));
    print_kv_colored("Stripped",
                     result.stripped ? "yes" : "no",
                     result.stripped ? console::yellow : console::green);
    if (!result.pdb_filename.empty()) print_kv("PDB", result.pdb_filename);
    if (!result.debug_sections.empty()) {
      std::string secs;
      for (const auto& s : result.debug_sections) {
        if (!secs.empty()) secs += ", ";
        secs += s;
      }
      print_kv("Debug sections", secs);
    }
  } else {
    const auto errs = extractor::get_error_messages(result);
    if (errs.empty()) {
      console::info("no debug symbols present");
    } else {
      console::error("debug symbol extraction failed");
      for (const auto& m : errs) console::error("  " + m);
    }
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 11: signature
// ---------------------------------------------------------------------------
void run_signature(context& ctx) {
  phase(ctx, true, "signature check");
  const auto started = report_clock::now();
  extractor::signature_info_t result{};
  if (extractor::extract_signature_info(result, ctx.info)) {
    print_kv("Format",     result.format);
    print_kv("Signatures", std::to_string(result.num_signatures));
    if (!result.signer.empty()) print_kv("Signer", result.signer);
    if (!result.issuer.empty()) print_kv("Issuer", result.issuer);
    if (!result.verification.empty())
      print_kv_colored("Verification", result.verification,
                       result.is_valid ? console::green : console::yellow);
    for (const auto& d : result.details) console::success(d);
  } else {
    console::info("not signed (" + result.format + ")");
  }
  print_duration(elapsed_ms(started));
}

}  // namespace pipeline
