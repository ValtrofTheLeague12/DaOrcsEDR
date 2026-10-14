#include "pipeline.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <ios>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "console.hpp"
#include "exporter.hpp"
#include "guards.hpp"

namespace pipeline {

namespace {

// Positive-integer seconds override from the environment. A missing,
// non-numeric, or out-of-range value keeps `fallback`.
std::chrono::seconds env_seconds(const char* name, long long fallback) {
  const char* raw = std::getenv(name);
  if (raw == nullptr || *raw == '\0') return std::chrono::seconds(fallback);
  char* end = nullptr;
  const long long parsed = std::strtoll(raw, &end, 10);
  if (end == raw || *end != '\0' || parsed <= 0 || parsed > 86400) {
    return std::chrono::seconds(fallback);
  }
  return std::chrono::seconds(parsed);
}

}  // namespace

// ---------------------------------------------------------------------------
// Phase 12: capa
// ---------------------------------------------------------------------------
void run_capa(context& ctx) {
  phase(ctx, true, "capa");
  const auto started = report_clock::now();
  capa::options capa_opts;
  capa_opts.executable            = "capa";
  capa_opts.cache_dir             = "cache/capa";
  capa_opts.cache_salt            = "v1";
  capa_opts.include_library_rules = false;
  capa_opts.max_addresses         = 32;
  capa_opts.max_stdout_bytes      = 64u * 1024u * 1024u;
  capa_opts.low_priority          = true;
  // The old fixed 300 s budget killed capa on obfuscated samples with zero
  // bytes of stdout (EasyAntiCheat_EOS.exe, 1 MB, timed out after 300 s).
  // Give the normal phase 15 min by default; CAPA_TIMEOUT and
  // CAPA_LARGE_TIMEOUT (seconds) override either phase.
  capa_opts.timeout               = env_seconds("CAPA_TIMEOUT", 900);
  capa_opts.large_timeout         = env_seconds("CAPA_LARGE_TIMEOUT", 1800);

  ctx.capa_report = capa::analyze_file(ctx.info.filepath, capa_opts);
  print_capa_report(ctx.capa_report);
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// radare2 option setup (shared by every phase that invokes r2)
// ---------------------------------------------------------------------------
void configure_r2(context& ctx) {
  ctx.r2_opts.executable            = "r2";
  ctx.r2_opts.rabin2                = "rabin2";
#ifdef _WIN32
  ctx.r2_opts.use_wsl               = true;
  if (const char* use_wsl = std::getenv("R2_USE_WSL");
      use_wsl != nullptr && std::string(use_wsl) == "0") {
    ctx.r2_opts.use_wsl = false;
  }
#else
  ctx.r2_opts.use_wsl               = false;
#endif
  ctx.r2_opts.quiet                 = true;
  ctx.r2_opts.analysis              = true;
  ctx.r2_opts.timeout               = std::chrono::milliseconds(180000);
  ctx.r2_opts.pin_analysis_config   = true;
  ctx.r2_opts.anal_timeout_ms       = 120000;

  if (!r2::find_executable(ctx.r2_opts).empty()) {
    ctx.r2_opts.r2_version = r2::version(ctx.r2_opts);
  }
  if (!r2::find_rabin2(ctx.r2_opts).empty()) {
    ctx.r2_opts.rabin2_version = r2::rabin2_version(ctx.r2_opts);
  }
}

// ---------------------------------------------------------------------------
// Phase 13: radare2 graphs
// ---------------------------------------------------------------------------
void run_radare2(context& ctx) {
  configure_r2(ctx);

  // ctx.stem is computed in run_hashes() now (so pipelines without this phase
  // have it too); this phase only needs the run directory it owns.
  ctx.out_dir = exporter::dir::run(ctx.stem, "radare2").string();

  phase(ctx, true, "radare2 disassembly");
  const auto started = report_clock::now();
  ctx.r2_result = r2::extract_all(ctx.info.filepath, ctx.out_dir, ctx.stem, ctx.r2_opts);
  print_radare2_report(ctx.r2_result);
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 14: graphviz rendering
// ---------------------------------------------------------------------------
void run_graphviz(context& ctx) {
  ctx.render_format = env_or_empty("R2_RENDER");
  if (ctx.render_format.empty()) return;

  phase(ctx, true, "graphviz rendering");

  const auto started = report_clock::now();
  std::string dot_exe = env_or_empty("R2_DOT_EXE");
  if (dot_exe.empty()) dot_exe = r2::default_dot();

  r2::section_dot_result_t dot_view;
  for (const auto& f : ctx.r2_result.files) {
    const bool is_dot =
        f.path.size() >= 4 &&
        f.path.compare(f.path.size() - 4, 4, ".dot") == 0;
    if (!is_dot) continue;

    r2::section_dot_file_t entry;
    entry.section = f.kind;
    entry.path    = f.path;
    entry.bytes   = f.bytes;
    entry.empty   = (f.bytes == 0);
    dot_view.files.push_back(std::move(entry));
  }
  dot_view.sections_considered = dot_view.files.size();

  if (dot_view.files.empty()) {
    console::info("no .dot files to render");
  } else if (dot_exe.empty()) {
    print_warn("graphviz 'dot' not found; skipping render "
               "(install Graphviz or set R2_DOT_EXE)");
  } else {
    const auto errors =
        r2::render_section_dots(dot_view, dot_exe, ctx.render_format);
    ctx.rendered_attempted = dot_view.files.size();
    ctx.rendered_ok = ctx.rendered_attempted - errors.size();
    print_render_report(ctx.render_format, ctx.rendered_ok, ctx.rendered_attempted, errors);
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 15: IAT/GOT call-site assembly
// ---------------------------------------------------------------------------
void run_xref_asm(context& ctx) {
  phase(ctx, true, "IAT/GOT call-site assembly");
  const auto started = report_clock::now();

  std::uint64_t pe_image_base = 0;
  if (ctx.is_pe) {
    r2::result_t meta = r2::analyze_file(ctx.info.filepath, ctx.r2_opts);
    if (meta.st == r2::status::ok) pe_image_base = meta.info.baddr;
  }

  std::vector<std::uint64_t> targets;
  const bool have_targets = collect_xref_targets(
      ctx.info, ctx.is_pe, ctx.is_elf, ctx.is_macho, pe_image_base, targets);

  if (!have_targets || targets.empty()) {
    console::info("no IAT/GOT targets to disassemble");
    ctx.xref_skipped = true;
  } else {
    r2::xref_asm_options dump;
    dump.max_slots               = 2000;
    dump.max_functions           = 500;
    dump.dedup_functions         = true;
    dump.include_addresses       = true;
    dump.include_function_header = true;

    ctx.xref_result = r2::dump_xref_calls(ctx.info.filepath, ctx.out_dir, ctx.stem,
                                          targets, ctx.r2_opts, dump);
    print_xref_asm_report(ctx.xref_result);
  }

  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 16: compilation guards
// ---------------------------------------------------------------------------
void run_guards(context& ctx) {
  phase(ctx, true, "compilation guards");
  const auto started = report_clock::now();
  extractor::guard_info_t result{};
  if (extractor::extract_guard_info(result, ctx.info)) {
    print_kv("Format", result.format);
    if (result.format == "PE") {
      std::ostringstream dc;
      dc << "0x" << std::hex << result.dll_characteristics_raw;
      print_kv("DllCharacteristics", dc.str());
    } else if (result.format == "ELF") {
      std::ostringstream xf;
      xf << "0x" << std::hex << result.x86_features_raw;
      print_kv("x86 features", xf.str());
    }
    if (result.notes.empty()) {
      print_kv_colored("Guards",
                       "none set - suspicious for modern software",
                       console::red);
    } else {
      print_section("active mitigations");
      for (const auto& note : result.notes) print_bullet(note, console::green);
    }

    // Explain what each mitigation actually does, and flag the risky ones.
    const auto descriptions = guard_descriptions(result);
    if (!descriptions.empty()) {
      print_kv("Mitigations",
               std::to_string(result.mitigations_enabled) + " of " +
                   std::to_string(result.mitigations_checked) + " checked");
      print_section("compilation guard details");
      std::ostringstream head;
      head << std::left << std::setw(26) << "Guard" << std::setw(6) << "State"
           << "What it does";
      print_bullet(head.str(), console::cyan);
      for (const auto& guard : descriptions) {
        const bool risky = std::strcmp(guard.name, "Executable stack") == 0 ||
                           std::strcmp(guard.name, "No bind") == 0 ||
                           std::strcmp(guard.name, "CET relax IP validation") == 0 ||
                           std::strcmp(guard.name, "Force integrity") == 0;
        const std::string state = guard.enabled ? "on" : "off";
        const std::string_view color = guard.enabled
                                           ? (risky ? console::yellow : console::green)
                                           : console::grey;
        std::ostringstream row;
        row << std::left << std::setw(26) << guard.name
            << std::setw(6) << state << guard.description;
        print_bullet(row.str(), color);
      }
    }
  } else {
    console::info("no compilation guards extracted (" + result.format + ")");
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Full extraction, then the two reports it produces
// ---------------------------------------------------------------------------
// The full pipeline runs here because the export table and the YARA results are
// both populated only by analyze(); there is no standalone extractor call for
// either.
void run_full_extraction(context& ctx) {
  extractor::analyze(ctx.full, ctx.info);

  // -------- Export Address Table (PE) --------
  phase(ctx, ctx.is_pe, "export table (PE)");
  {
    const auto started = report_clock::now();
    if (ctx.is_pe) print_export_report(ctx.full.pe.export_table);
    print_duration(elapsed_ms(started));
  }

  // -------- YARA rules --------
  // Also produced by analyze(); previously surfaced only in the exported JSON
  // and the dashboard, never in the terminal or PDCurses.
  phase(ctx, ctx.is_pe, "YARA rule scan");
  {
    const auto started = report_clock::now();
    if (ctx.is_pe) print_yara_report(ctx.full.yara);
    print_duration(elapsed_ms(started));
  }
}

// ---------------------------------------------------------------------------
// Phase 17: hexdump
// ---------------------------------------------------------------------------
// The extractor already read the head of the file into ctx.full.hexdump;
// surface it as a real report section so it is visible in the terminal and in
// the PDCurses results browser (it is also exported inside the extraction
// JSON). The rows are built from the bytes directly, so there is no tool to
// locate and no text to re-parse.
void run_hexdump(context& ctx) {
  phase(ctx, true, "hexdump");
  const auto started = report_clock::now();
  const auto& dump = ctx.full.hexdump;
  print_section("Hexdump");
  if (!dump.attempted) {
    console::info("no hexdump was attempted for this file");
  } else if (!dump.available) {
    print_warn("hexdump unavailable: the file could not be read");
    for (const auto& message : extractor::get_error_messages(dump.errors))
      console::error(message);
  } else {
    std::ostringstream meta;
    meta << dump.bytes.size() << " of " << dump.total_bytes << " byte(s)"
         << "  base=0x" << std::hex << dump.base << std::dec
         << "  " << dump.bytes_per_row << "/row"
         << "  " << std::fixed << std::setprecision(3) << dump.seconds << "s";
    print_kv("Window", meta.str());
    print_kv("Truncated", dump.truncated ? "yes (sample is larger)" : "no");

    const std::size_t per_row =
        dump.bytes_per_row == 0 ? std::size_t{16} : dump.bytes_per_row;
    const std::size_t rows = dump.bytes.size() / per_row;
    constexpr std::size_t kMaxRows = 64;
    const std::size_t shown = std::min(rows, kMaxRows);
    for (std::size_t r = 0; r < shown; ++r) {
      print_hexdump_row(dump.base + r * per_row,
                        dump.bytes.data() + r * per_row, per_row, per_row);
    }
    // A partial final row still deserves to be shown; it is where the file's
    // last captured byte lives.
    const std::size_t tail = dump.bytes.size() - rows * per_row;
    if (tail > 0 && shown == rows) {
      print_hexdump_row(dump.base + rows * per_row,
                        dump.bytes.data() + rows * per_row, tail, per_row);
    }
    if (shown < rows) {
      print_bullet("... more rows follow (the full window is in the extraction JSON)",
                   console::grey);
    }
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 18: cminer code caves
// ---------------------------------------------------------------------------
void run_cminer(context& ctx) {
  phase(ctx, true, "cminer code caves");
  const auto started = report_clock::now();
  const auto& caves = ctx.full.cminer;
  print_section("Cminer");
  if (!caves.attempted) {
    console::info("cminer was not attempted for this file");
  } else if (!caves.applicable) {
    console::info("cminer only analyzes PE files; skipped");
  } else if (!caves.available) {
    print_warn("cminer cave scan failed");
    if (!caves.command.empty()) print_kv("Command", caves.command);
    if (!caves.stderr_tail.empty()) print_kv("Stderr", caves.stderr_tail);
  } else {
    print_kv("Command", caves.command);
    std::ostringstream meta;
    meta << "exit=" << caves.exit_code << "  seconds=" << std::fixed
         << std::setprecision(3) << caves.seconds
         << "  min_cave_size=" << caves.minimum_cave_size;
    print_kv("Scan", meta.str());
    print_kv("Caves found", std::to_string(caves.caves.size()));
    print_kv("Total cave bytes", std::to_string(caves.total_cave_bytes));
    print_kv("Largest cave", std::to_string(caves.largest_cave_bytes));
    if (caves.caves.empty()) {
      console::info("no code caves at or above the minimum size");
    } else {
      print_section("Code caves");
      std::ostringstream head;
      head << std::left << std::setw(18) << "Section" << std::right
           << std::setw(8) << "Size" << std::setw(14) << "Start"
           << std::setw(14) << "End" << std::setw(12) << "FileOff";
      print_bullet(head.str(), console::cyan);
      constexpr std::size_t kMaxCaves = 20;
      std::size_t shown = 0;
      for (const auto& cave : caves.caves) {
        if (shown >= kMaxCaves) break;
        std::ostringstream row;
        row << std::left << std::setw(18) << cave.section << std::right
            << std::setw(8) << cave.size
            << "  0x" << std::hex << std::setw(10) << cave.start_address
            << "  0x" << std::setw(10) << cave.end_address
            << "  0x" << std::setw(8) << cave.file_offset << std::dec;
        print_bullet(row.str());
        ++shown;
      }
      if (shown < caves.caves.size()) {
        print_bullet("... and " + std::to_string(caves.caves.size() - shown) +
                     " more (all caves are in the extraction JSON)");
      }
    }
    // The raw tool output is kept alongside the parsed table.
    print_cminer_raw(caves.output);
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 19: pipeline error recovery
// ---------------------------------------------------------------------------
void run_error_recovery(context& ctx) {
  phase(ctx, true, "pipeline error recovery");
  const auto started = report_clock::now();
  const auto errors = extractor::recover_errors(ctx.full);
  if (errors.empty()) console::success("no pipeline errors");
  else {
    console::print_tree_header("stage errors");
    console::print_tree_stages(errors);
  }
  print_duration(elapsed_ms(started));
}

}  // namespace pipeline
