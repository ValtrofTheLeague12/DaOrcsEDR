#include "guards.hpp"
#include "report.hpp"

#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>

// ---------------------------------------------------------------------------
// PE trailer report
// ---------------------------------------------------------------------------
// Phase-1 PE trailer report: section boundaries, the Authenticode Security
// Directory range, and the extracted overlay with its detected formats.
void print_pe_overlay_report(const extractor::pe_sections_t& result) {
  print_section("PE section end / overlay");
  std::ostringstream os;
  os << "file_size=" << result.file_size
     << "  last_section_end=" << result.last_section_end;
  print_kv("Section boundary", os.str());
  print_kv_colored("Overlay detected",
                   result.has_computed_overlay ? "yes" : "no",
                   result.has_computed_overlay ? console::yellow : console::white);
  if (result.has_computed_overlay) {
    std::ostringstream range;
    range << result.computed_overlay_size << " bytes  start=0x" << std::hex
          << result.computed_overlay_start << "  end=0x" << result.computed_overlay_end;
    print_kv("Overlay range", range.str());
    print_kv("LIEF overlay match", result.overlay_size_matches ? "yes" : "no");
  }

  const auto& sec = result.security_directory;
  print_section("PE Security Directory");
  if (!sec.present) {
    console::info("no Authenticode Security Directory present");
  } else {
    std::ostringstream cert;
    cert << "offset=0x" << std::hex << sec.file_offset << "  size=" << std::dec
         << sec.size << "  end=0x" << std::hex << sec.end_offset;
    print_kv("Certificate range", cert.str());
    print_kv("Range valid", sec.valid_range ? "yes" : "no");
    print_kv("Overlaps section", sec.overlaps_section ? "yes" : "no");
    print_kv("Inside section overlay", sec.inside_section_overlay ? "yes" : "no");
    print_kv("Certificate entries", std::to_string(sec.certificate_count));
    for (const std::string& warning : sec.warnings) print_warn(warning);
  }
  if (result.has_overlay_after_security) {
    std::ostringstream after;
    after << result.overlay_after_security_size << " bytes  start=0x" << std::hex
          << result.overlay_after_security_start;
    print_kv("Data after signature", after.str());
  }

  print_section("PE overlay extraction");
  const auto& overlay = result.overlay;
  if (!overlay.present) {
    console::info("no overlay bytes available to extract or identify");
    return;
  }

  std::ostringstream head;
  head << "offset=0x" << std::hex << overlay.offset << "  size=" << std::dec
       << overlay.size << "  retained=" << overlay.data.size();
  print_kv("Overlay data", head.str());
  print_kv("Magic", overlay.magic_hex + "  [" + overlay.magic_ascii + "]");
  console::print_entropy_and_chi2(overlay.entropy, overlay.chi2);
  if (!overlay.sha256.empty()) print_kv("Overlay SHA-256", overlay.sha256);
  if (overlay.truncated) {
    print_warn("overlay exceeds the retention limit; scan used a bounded prefix");
  }

  if (overlay.signatures.empty()) {
    console::info("no known file format identified inside the overlay");
    return;
  }
  print_kv("Formats identified", std::to_string(overlay.signatures.size()));
  print_section("Overlay formats");
  for (const auto& sig : overlay.signatures) {
    std::ostringstream line;
    line << sig.format << "  " << sig.description
         << "  offset=0x" << std::hex << sig.offset
         << " (+" << std::dec << sig.relative_offset << ")"
         << "  size=" << sig.size
         << "  confidence=" << std::fixed << std::setprecision(2) << sig.confidence;
    print_bullet(line.str());
  }
}

// ---------------------------------------------------------------------------
// Compilation guards
// ---------------------------------------------------------------------------
// guard_descriptions() and its struct live in guards.hpp because the guards
// phase needs the description text as data, not just as printed output.

std::vector<guard_description_t> guard_descriptions(
    const extractor::guard_info_t& g) {
  std::vector<guard_description_t> out;
  auto add = [&](const char* name, bool enabled, const char* description) {
    out.push_back({name, enabled, description});
  };

  if (g.format == "PE") {
    add("ASLR", g.has_aslr,
        "randomizes the image load address to block fixed-address exploits");
    add("High-entropy ASLR", g.has_high_entropy_va,
        "uses the full 64-bit address space, making brute force impractical");
    add("DEP/NX", g.has_nx,
        "marks data pages non-executable to stop shellcode in data regions");
    add("Force integrity", g.has_force_integrity,
        "requires a valid code signature at load time (anti-tamper)");
    add("Isolation aware", g.has_isolation,
        "enables side-channel isolation checks for Spectre-class mitigations");
    add("SEH", !g.has_no_bind,
        "uses Structured Exception Handling instead of bind-based exception tables");
    add("No bind", g.has_no_bind,
        "omits bind-based image binding; older exception model");
    add("Control Flow Guard", g.has_guard_cf,
        "validates indirect call targets against a known-function bitmap");
    add("CET shadow stack", g.has_cet_compat,
        "Intel CET hardware shadow stack for return-address protection");
    add("CET strict mode", g.cet_strict_mode,
        "enables strict CET shadow-stack enforcement");
    add("CET relax IP validation", g.cet_set_context_ip_validation_relaxed,
        "relaxes CET IP validation for compatibility (weakens the guarantee)");
    add("CET dynamic APIs in-process", g.cet_dynamic_apis_allow_in_proc,
        "allows dynamic APIs to run inside the guarded process");
    add("WDM driver", g.has_wdm_driver,
        "marks the image as a WDM driver, changing loader behaviour");
  } else if (g.format == "ELF") {
    add("PIE", g.has_pie,
        "Position Independent Executable: ASLR works with the image base");
    add("RELRO", g.has_relro,
        "makes the GOT read-only after relocations to stop GOT overwrites");
    add("Full RELRO", g.has_full_relro,
        "RELRO covering the entire GOT, not just parts of it");
    add("Stack canary", g.has_stack_canary,
        "stack cookie detects buffer overflows before a function returns");
    add("SafeSEH", g.has_safe_seh,
        "validates Structured Exception Handler addresses against a known table");
    add("FORTIFY_SOURCE", g.has_fortify,
        "compile-time bounds checking for common C library functions");
    add("RPATH/RUNPATH", g.has_rpath,
        "search-path entries baked into the binary (can redirect libraries)");
    add("Executable stack", g.executable_stack,
        "stack is executable: enables classic stack shellcode execution");
    add("SHSTK", g.has_shstk,
        "hardware shadow stack (CET) return-address protection");
    add("IBT", g.has_ibt || g.has_bti,
        "indirect branch tracking: only indirect branches to valid targets run");
    add("PAC", g.has_pac,
        "pointer authentication codes protect return addresses and pointers");
  }
  add("Stack cookie", g.has_stack_cookie,
      "canary value on the stack to detect stack smashing");
  return out;
}

// ---------------------------------------------------------------------------
// PE export address table report
// ---------------------------------------------------------------------------
// The EAT is parsed by the extraction pipeline and serialized into the
// extraction JSON (raw.pe.export_table), and the dashboard renders it, but the
// terminal and PDCurses never mentioned it: there were no references to
// export_table anywhere in the reporting code.
void print_export_report(const extractor::pe_export_table_t& r) {
  print_section("Export table");
  if (!r.present) {
    console::info("no export address table (expected for a plain executable)");
    return;
  }

  print_kv("Name", r.name.empty() ? "(unnamed)" : r.name);
  std::ostringstream ts;
  ts << "0x" << std::hex << std::setw(8) << std::setfill('0') << r.timestamp
     << std::dec << std::setfill(' ');
  print_kv("Timestamp", ts.str());
  print_kv("Version",
           std::to_string(r.major_version) + "." + std::to_string(r.minor_version));
  print_kv("Ordinal base", std::to_string(r.ordinal_base));

  std::ostringstream at;
  at << hex_rva(r.export_addr_table_rva) << "  " << r.export_addr_table_count
     << " entries";
  print_kv("Address table", at.str());
  std::ostringstream nt;
  nt << hex_rva(r.names_addr_table_rva) << "  " << r.names_addr_table_count
     << " entries";
  print_kv("Name table", nt.str());
  print_kv("Ordinal table", hex_rva(r.ordinal_addr_table_rva));

  std::ostringstream counts;
  counts << r.named_count << " named  |  " << r.forwarded_count << " forwarded"
         << "  |  " << r.external_count << " external";
  print_kv_colored("Entries", counts.str(), console::green);
  print_kv("Total entries", std::to_string(r.entries.size()));
  if (r.entries.empty()) return;

  print_section("Exported symbols");
  // Kept in step with the dashboard's 2000-entry preview cap.
  constexpr std::size_t kMaxExports = 2000;
  std::size_t shown = 0;
  for (const auto& e : r.entries) {
    if (shown >= kMaxExports) {
      print_bullet("... more exports (full list is in the extraction JSON)",
                   console::grey);
      break;
    }
    std::ostringstream line;
    line << std::left << std::setw(6) << e.ordinal << "  " << hex_rva(e.rva)
         << "  " << (e.name.empty() ? "(ordinal only)" : e.name);
    std::string_view color = console::white;
    if (e.is_forwarded) {
      line << "  -> " << e.forwarder_library;
      if (!e.forwarder_function.empty()) line << "." << e.forwarder_function;
      color = console::yellow;
    } else if (e.is_extern) {
      color = console::red;
    }
    print_bullet(line.str(), color);
    ++shown;
  }
}
