#include "pipeline.hpp"

#include <cstddef>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "cyberchef.hpp"
#include "console.hpp"
#include "ioc_extractor.hpp"
#include "logging.hpp"

namespace pipeline {

// ---------------------------------------------------------------------------
// Preamble: banner, file identity, format detection, phase plan
// ---------------------------------------------------------------------------
void run_preamble(context& ctx) {
  print_banner("static analyzer");
  print_kv("Input",  ctx.path);
  print_kv("Run ID", logging::current_run_id());

  ctx.info   = analyzer::get_file_info(ctx.path);
  ctx.failed = analyzer::has_errors(ctx.info);

  print_section("file");
  print_kv("Name",  ctx.info.filename);
  print_kv("Magic", ctx.info.file_magic);
  print_kv_colored("Executable",
                   ctx.info.type.is_executable ? "yes" : "no",
                   ctx.info.type.is_executable ? console::green : console::yellow);

  console::print_magic_header(ctx.info);
  console::print_magic_offset(ctx.info);

  if (ctx.failed) {
    print_kv_colored("Status", "ANALYSIS FAILED", console::red);
    console::print_available_fields(ctx.info);
    for (const auto& error : analyzer::get_error_messages(ctx.info))
      console::error(error);
    if (!ctx.info.errors.details.empty())
      console::error("Details: " + ctx.info.errors.details);
  } else {
    print_kv_colored("Status", "ok", console::green);
  }

  ctx.fmt     = detect_format(ctx.info);
  ctx.is_pe   = (ctx.fmt == file_format::pe);
  ctx.is_elf  = (ctx.fmt == file_format::elf);
  ctx.is_macho = (ctx.fmt == file_format::macho);

  print_kv("Format", format_name(ctx.fmt));

  // -------- Format-aware phase plan ----------------------------------------
  // The PDCurses results screen turns every printed "[phase n/total]" header
  // into its own section, so a header emitted for a stage that cannot run would
  // advertise work that never happened (an ELF listing "IAT / Import Table
  // (PE)", a PE listing "GOT / PLT (ELF, Mach-O)"). Only the stages that
  // concern this binary are numbered and counted, which also makes the
  // progress bar reflect real work instead of the fixed 25-stage pipeline.
  //
  //   PE / ELF / Mach-O : phase 1 renders the format-specific section table, so
  //                       the generic LIEF view (phase 2) is a duplicate.
  //   PE                : import table (4), MalAPI (5), the export address
  //                       table and the YARA rule scan.
  //   ELF / Mach-O      : GOT / PLT (6).
  constexpr int kAllPhases = 25;
  const int kSkippedGenericSections = (ctx.is_pe || ctx.is_elf || ctx.is_macho) ? 1 : 0;
  const int kSkippedPeOnly = ctx.is_pe ? 0 : 4;                 // IAT, MalAPI, EAT, YARA
  const int kSkippedGotOnly = (ctx.is_elf || ctx.is_macho) ? 0 : 1;  // GOT / PLT
  ctx.total_phases = kAllPhases - kSkippedGenericSections
                   - kSkippedPeOnly - kSkippedGotOnly;
  if (ctx.curses != nullptr) {
    ctx.curses->set_total(static_cast<std::size_t>(ctx.total_phases));
  }
}

// ---------------------------------------------------------------------------
// Hashes - printed before phase 1, not numbered as a phase of their own
// ---------------------------------------------------------------------------
void run_hashes(context& ctx) {
  if (hasher::hash_file(ctx.file_hash, ctx.info)) {
    print_kv("SHA-256", ctx.file_hash.hash);
  } else {
    print_kv_colored("SHA-256", "failed", console::red);
    for (const auto& message : hasher::get_hash_error_messages(ctx.file_hash))
      console::error(message);
  }

  if (hasher::fuzzy_hash_file(ctx.fuzzy_hash, ctx.info)) {
    print_kv("TLSH", ctx.fuzzy_hash.fuzzy_hash);
  } else {
    print_kv_colored("TLSH", "failed", console::red);
    for (const auto& message : hasher::get_fuzzy_hash_error_messages(ctx.fuzzy_hash))
      console::error(message);
  }
}

// ---------------------------------------------------------------------------
// Phase 1: sections
// ---------------------------------------------------------------------------
void run_sections(context& ctx) {
  phase(ctx, true,
        ctx.is_pe ? "PE sections"
        : ctx.is_elf ? "ELF sections"
        : ctx.is_macho ? "Mach-O sections"
        : "sections");
  const auto started = report_clock::now();
  if (ctx.is_pe) {
    extractor::pe_sections_t result{};
    if (extractor::extract_pe_sections(result, ctx.info)) {
      print_section("PE: " + result.machine + "  " + result.characteristics);
      std::ostringstream ep;
      ep << "0x" << std::hex << result.entrypoint;
      print_kv("Entrypoint", ep.str());
      for (const auto& section : result.sections) {
        std::cout << "      " << std::left << std::setw(10) << section.name
                  << "  va=0x" << std::hex << section.virtual_address
                  << std::dec
                  << "  vsize=" << section.virtual_size
                  << "  raw=" << section.raw_size << '\n';
        console::print_entropy_and_chi2(section.entropy, section.chi2);
      }
      print_pe_overlay_report(result);
    } else {
      for (const auto& message : extractor::get_error_messages(result))
        console::error(message);
    }
  } else if (ctx.is_elf) {
    extractor::elf_sections_t result{};
    if (extractor::extract_elf_sections(result, ctx.info)) {
      print_section("ELF: " + result.machine + "  " + result.file_type);
      std::ostringstream ep;
      ep << "0x" << std::hex << result.entrypoint;
      print_kv("Entrypoint", ep.str());
      if (!result.interpreter.empty()) print_kv("Interpreter", result.interpreter);
      for (const auto& section : result.sections) {
        std::cout << "      " << std::left << std::setw(10) << section.name
                  << "  va=0x" << std::hex << section.virtual_address
                  << std::dec
                  << "  size=" << section.size
                  << "  type=" << section.type
                  << "  flags=" << section.flags << '\n';
        console::print_entropy_and_chi2(section.entropy, section.chi2);
      }
    } else {
      for (const auto& message : extractor::get_error_messages(result))
        console::error(message);
    }
  } else if (ctx.is_macho) {
    extractor::sections_result_t result{};
    if (extractor::extract_sections(result, ctx.info)) {
      print_section("Mach-O: " + std::to_string(result.sections.size()) + " sections");
      for (const auto& section : result.sections) {
        std::cout << "      " << std::left << std::setw(10) << section.name
                  << "  va=0x" << std::hex << section.virtual_address
                  << std::dec
                  << "  size=" << section.size
                  << "  H=" << section.entropy << '\n';
        console::print_entropy_and_chi2(section.entropy, section.chi2);
      }
    } else {
      for (const auto& message : extractor::get_error_messages(result))
        console::error(message);
    }
  } else {
    console::info("no format-specific section view for " + std::string(format_name(ctx.fmt)));
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 2: format-agnostic section table
// ---------------------------------------------------------------------------
// Phase 1 already renders a format-specific section table (PE / ELF / Mach-O)
// including flags and permissions. Re-printing the same sections through the
// generic LIEF view only produced a duplicate, so it is skipped for the three
// formats that have a dedicated view and kept for everything else.
void run_generic_sections(context& ctx) {
  phase(ctx, !(ctx.is_pe || ctx.is_elf || ctx.is_macho), "generic sections");
  const auto started = report_clock::now();
  if (!(ctx.is_pe || ctx.is_elf || ctx.is_macho)) {
    extractor::sections_result_t result{};
    if (extractor::extract_sections(result, ctx.info)) {
      print_section("Sections: " + std::to_string(result.sections.size()));
      for (const auto& section : result.sections) {
        std::cout << "      " << std::left << std::setw(10) << section.name
                  << "  va=0x" << std::hex << section.virtual_address
                  << std::dec
                  << "  size=" << section.size
                  << "  H=" << std::fixed << std::setprecision(4) << section.entropy
                  << "  chi2=" << std::setprecision(0) << section.chi2 << '\n';
      }
    } else {
      for (const auto& message : extractor::get_error_messages(result))
        console::error(message);
    }
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 3: strings + IOC
// ---------------------------------------------------------------------------
void run_strings_and_ioc(context& ctx) {
  phase(ctx, true, "strings + IOC");
  std::vector<std::string> strings_for_ioc{};
  {
    const auto started = report_clock::now();
    extractor::strings_result_t result{};
    if (extractor::extract_strings(result, ctx.info, 6)) {
      print_kv_colored("Strings found",
                       std::to_string(result.strings.size()),
                       console::green);
      constexpr std::size_t kMaxShown = 10;
      std::size_t shown = 0;
      for (const auto& entry : result.strings) {
        if (shown >= kMaxShown) break;
        std::ostringstream os;
        os << "[" << std::setw(8) << std::dec << entry.offset << "] " << entry.value;
        print_bullet(os.str());
        ++shown;
      }
      if (result.strings.size() > shown)
        print_bullet("... and " + std::to_string(result.strings.size() - shown) + " more");

      // Move (not copy) the values into the IOC/MalAPI working set: the
      // preview above is already printed, so keeping a second full copy of
      // every extracted string is pure overhead. Halves peak memory here.
      strings_for_ioc.reserve(result.strings.size());
      for (auto& entry : result.strings)
        strings_for_ioc.push_back(std::move(entry.value));
    } else {
      for (const auto& message : extractor::get_error_messages(result))
        console::error(message);
    }
    print_duration(elapsed_ms(started));
  }

  if (!strings_for_ioc.empty()) {
    const auto started = report_clock::now();
    ctx.ioc_results = ioc::extract_all(strings_for_ioc);
    if (ioc::has_errors(ctx.ioc_results)) {
      console::error("IOC extraction had errors");
      for (const auto& msg : ioc::get_error_messages(ctx.ioc_results))
        console::error(msg);
    } else {
      print_section("IOC extraction");
      ioc::print_ioc_results(ctx.ioc_results);
      if (!ctx.ioc_results.ips.empty()) {
        print_section("IP network information");
        for (const std::string& ip : ctx.ioc_results.ips) {
          print_ip_network_info(ip, cti::ip_network_context(ip));
        }
      }
    }
    print_duration(elapsed_ms(started));
  } else {
    print_warn("no candidate strings available for IOC extraction");
  }

  // CyberChef pass: decode candidate strings through the local
  // CyberChef-server (if it is running) and flag the ones whose decoded
  // form hides a launcher / download cradle / shell. Best-effort: the
  // container is external tooling, so an unreachable server costs one
  // warning line and the analysis continues.
  if (!strings_for_ioc.empty()) {
    const auto started = report_clock::now();
    cyberchef::scan_result_t scan = cyberchef::scan(strings_for_ioc);
    if (scan.skipped) {
      LOG_DEBUG("cyberchef: scan skipped: {}", scan.error);
    } else if (!scan.server_ok) {
      print_warn("CyberChef API unreachable (" + scan.error +
                 "); encoded-string flagging skipped");
    } else {
      ctx.ioc_results.encoded_flags = std::move(scan.flagged);
      print_section("Encoded strings (CyberChef)");
      print_kv_colored(
          "Checked",
          std::to_string(scan.candidates_rot) + " rot + " +
              std::to_string(scan.candidates_magic) +
              " encoded candidate(s) in " + std::to_string(scan.calls) +
              " request(s)",
          console::green);
      print_kv_colored("Flagged", std::to_string(scan.flags),
                       scan.flags != 0 ? console::red : console::green);
      auto one_line = [](std::string s) {
        for (char& c : s)
          if (c == '\n' || c == '\r') c = ' ';
        if (s.size() > 240) s = s.substr(0, 240) + "...";
        return s;
      };
      for (const auto& f : ctx.ioc_results.encoded_flags) {
        print_bullet("[" + f.recipe + "] " + one_line(f.original));
        print_bullet("    decoded: " + one_line(f.decoded));
        std::string hits;
        for (const auto& ind : f.indicators) {
          if (!hits.empty()) hits += ", ";
          hits += ind;
        }
        print_bullet("    indicators: " + hits);
      }
    }
    print_duration(elapsed_ms(started));
  }

  // IOC extraction was the last consumer of the extracted strings - release
  // them before the memory-heavy capa / radare2 phases.
  strings_for_ioc.clear();
  strings_for_ioc.shrink_to_fit();
}

}  // namespace pipeline
