#include "report.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <map>
#include <sstream>
#include <string>
#include <system_error>

#include "logging.hpp"

// SearchPathW / GetSystemDirectoryW (host DLL existence check) live in the
// Win32 API. NOMINMAX keeps windows.h from defining min/max as macros.
#ifdef _WIN32
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
#endif

namespace {

// ---------------------------------------------------------------------------
// Host DLL existence check
// ---------------------------------------------------------------------------
// The import table says which DLLs a PE asks for; this answers a different
// question - can the machine running the analyzer actually satisfy those
// names? The lookup never loads or executes anything: it only applies the
// loader's default search rules (SearchPathW) and the known system
// directories, so the verdict always describes the host, never the sample.

struct host_dll_status_t {
  bool        found = false;
  std::string detail;   // resolved path, an explanation, or the reason it failed
};

struct dll_group {
  std::uint64_t iat_base = 0;
  std::uint64_t ilt_base = 0;
  std::uint32_t timestamp = 0;
  std::uint32_t forwarder = 0;
  std::vector<const extractor::iat_entry_t*> regular;
  std::vector<const extractor::iat_entry_t*> delay;
};

host_dll_status_t check_host_dll(const std::string& dll) {
  host_dll_status_t status;
  if (dll.empty()) {
    status.detail = "no name in the import descriptor";
    return status;
  }

  std::string lower = dll;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

  // API-set / extension contracts (api-ms-*, ext-ms-*) are virtual DLLs: the
  // loader maps them onto real binaries (ucrtbase, kernelbase, ...) and no
  // file of that name ever exists on disk, so a plain existence test would
  // wrongly report them as missing.
  if (lower.rfind("api-ms-", 0) == 0 || lower.rfind("ext-ms-", 0) == 0) {
    status.found = true;
    status.detail = "API-set contract (mapped by the loader, no file on disk)";
    return status;
  }

#ifdef _WIN32
  const auto wide_to_utf8 = [](const wchar_t* text, int length) {
    const int bytes =
        WideCharToMultiByte(CP_UTF8, 0, text, length, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return std::string();
    std::string out(static_cast<std::size_t>(bytes), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, length, out.data(), bytes, nullptr, nullptr);
    return out;
  };

  // PE import names are ASCII, so widening byte-for-byte is lossless.
  const std::wstring wide(dll.begin(), dll.end());

  // SearchPathW applies the loader's default search order: application
  // directory, current directory, System32, System, Windows, then PATH.
  std::vector<wchar_t> buffer(4096);
  DWORD len = SearchPathW(nullptr, wide.c_str(), nullptr,
                          static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
  if (len > 0 && static_cast<std::size_t>(len) >= buffer.size()) {
    buffer.assign(static_cast<std::size_t>(len) + 1, L'\0');
    len = SearchPathW(nullptr, wide.c_str(), nullptr,
                      static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
  }
  if (len > 0 && static_cast<std::size_t>(len) < buffer.size()) {
    status.found = true;
    status.detail = wide_to_utf8(buffer.data(), static_cast<int>(len));
    return status;
  }

  // SearchPathW can miss DLLs that are on disk (broken PATH entries, unusual
  // search flags), so fall back to the directories the loader always consults.
  wchar_t folder[MAX_PATH + 1] = {};
  const UINT system_len = GetSystemDirectoryW(folder, MAX_PATH);
  if (system_len > 0 && system_len < MAX_PATH) {
    std::error_code ec;
    const std::filesystem::path candidate =
        std::filesystem::path(std::wstring(folder, system_len)) / dll;
    if (std::filesystem::exists(candidate, ec) && !ec) {
      status.found = true;
      status.detail =
          wide_to_utf8(candidate.c_str(), static_cast<int>(candidate.native().size()));
      return status;
    }
  }
  // A 32-bit sample on a 64-bit host loads from SysWOW64, which a 64-bit
  // System32 lookup never sees.
  const UINT windows_len = GetWindowsDirectoryW(folder, MAX_PATH);
  if (windows_len > 0 && windows_len < MAX_PATH) {
    std::error_code ec;
    const std::filesystem::path candidate =
        std::filesystem::path(std::wstring(folder, windows_len)) / L"SysWOW64" / dll;
    if (std::filesystem::exists(candidate, ec) && !ec) {
      status.found = true;
      status.detail =
          wide_to_utf8(candidate.c_str(), static_cast<int>(candidate.native().size()));
      return status;
    }
  }

  status.detail = "not found in the application, system or PATH directories";
  return status;
#else
  // Non-Windows host: the Windows loader search cannot run here, so only the
  // usual library directories are probed.
  for (const char* dir : {"/usr/lib", "/usr/lib64", "/lib",
                          "/usr/lib/x86_64-linux-gnu"}) {
    std::error_code ec;
    const std::filesystem::path candidate = std::filesystem::path(dir) / dll;
    if (std::filesystem::exists(candidate, ec) && !ec) {
      status.found = true;
      status.detail = candidate.string();
      return status;
    }
  }
  status.detail = "not found in the usual library directories";
  return status;
#endif
}

}  // namespace

// ---------------------------------------------------------------------------
// IAT rendering
// ---------------------------------------------------------------------------

void print_iat_report(const extractor::iat_result_t& r) {
  if (r.entries.empty() && r.dll_count == 0 && r.delay_dll_count == 0) {
    console::info("no import table entries");
    return;
  }

  print_section("import table summary");
  std::ostringstream counts;
  counts << r.dll_count << " DLLs"
         << "  |  " << r.named_import_count << " by name"
         << "  |  " << r.ordinal_import_count << " by ordinal";
  if (r.delay_dll_count > 0) {
    counts << "  |  " << r.delay_dll_count << " delay DLLs"
           << "  |  " << r.delay_import_count << " delay imports";
  }
  print_kv_colored("Entries", counts.str(), console::green);
  print_kv("Total entries", std::to_string(r.entries.size()));
  if (r.iat_lowest_rva != 0 || r.iat_highest_rva != 0) {
    print_kv("IAT range",
             hex_rva(r.iat_lowest_rva) + " .. " + hex_rva(r.iat_highest_rva));
  }
  if (r.truncated)
    print_kv_colored("Truncated", "yes (max entries reached)", console::yellow);

  // Host-side availability of every distinct DLL named by the import
  // descriptors (regular and delay-load alike). The [+]/[-] markers are what
  // the PDCurses results view colours on, since it strips the ANSI codes.
  std::map<std::string, host_dll_status_t> host_status;
  for (const auto& e : r.entries) host_status.emplace(e.dll, check_host_dll(e.dll));
  if (!host_status.empty()) {
    std::size_t found = 0;
    std::string missing;
    for (const auto& [dll, status] : host_status) {
      if (status.found) {
        ++found;
      } else {
        if (!missing.empty()) missing += ", ";
        missing += dll;
      }
    }
    std::ostringstream host_counts;
    if (missing.empty()) {
      host_counts << "[+] " << found << " of " << host_status.size()
                  << " present on this host";
      print_kv_colored("Host DLLs", host_counts.str(), console::green);
    } else {
      host_counts << "[-] " << found << " of " << host_status.size()
                  << " present on this host - missing: " << missing;
      print_kv_colored("Host DLLs", host_counts.str(), console::red);
    }
  }

  std::map<std::string, dll_group> groups;
  for (const auto& e : r.entries) {
    auto& g = groups[e.dll];
    if (g.iat_base == 0 && e.iat_base != 0) g.iat_base = e.iat_base;
    if (g.ilt_base == 0 && e.ilt_rva != 0) g.ilt_base = e.ilt_rva;
    if (g.timestamp == 0 && e.timestamp != 0) g.timestamp = e.timestamp;
    if (g.forwarder == 0 && e.forwarder != 0) g.forwarder = e.forwarder;
    if (e.is_delay) g.delay.push_back(&e);
    else            g.regular.push_back(&e);
  }

  constexpr std::size_t kMaxEntriesPerDll = 40;

  for (const auto& [dll, g] : groups) {
    print_section("DLL: " + dll);
    std::ostringstream head;
    head << "iat_base=" << hex_rva(g.iat_base)
         << "  int_base=" << hex_rva(g.ilt_base);
    if (g.timestamp != 0) head << "  bound_ts=" << std::hex << g.timestamp << std::dec;
    if (g.forwarder != 0) head << "  fwd=0x" << std::hex << g.forwarder << std::dec;
    print_kv("Descriptor", head.str());

    const auto host = host_status.find(dll);
    if (host != host_status.end()) {
      const std::string marker = host->second.found ? "[+] " : "[-] ";
      print_kv_colored("Host", marker + host->second.detail,
                       host->second.found ? console::green : console::red);
    }

    if (!g.regular.empty()) {
      print_bullet("regular imports (" + std::to_string(g.regular.size()) + ")",
                   console::grey);
      std::size_t shown = 0;
      for (const auto* e : g.regular) {
        if (shown++ >= kMaxEntriesPerDll) break;
        std::ostringstream line;
        line << "IAT=" << hex_rva(e->iat_rva)
             << "  val=" << hex_value(e->iat_value)
             << "  INT=" << hex_rva(e->int_rva) << "  ";
        if (e->is_ordinal || e->name.empty())
          line << "#" << e->ordinal << "  (ordinal)";
        else {
          line << e->name;
          if (e->hint != 0) line << "  hint=" << e->hint;
        }
        print_bullet(line.str());
      }
      if (g.regular.size() > shown)
        print_bullet("... and " + std::to_string(g.regular.size() - shown) + " more");
    }

    if (!g.delay.empty()) {
      print_bullet("delay-loaded imports (" + std::to_string(g.delay.size()) + ")",
                   console::yellow);
      std::size_t shown = 0;
      for (const auto* e : g.delay) {
        if (shown++ >= kMaxEntriesPerDll) break;
        std::ostringstream line;
        line << "val=" << hex_value(e->iat_value) << "  ";
        if (e->is_ordinal || e->name.empty())
          line << "#" << e->ordinal << "  (ordinal)";
        else {
          line << e->name;
          if (e->hint != 0) line << "  hint=" << e->hint;
        }
        print_bullet(line.str(), console::yellow);
      }
      if (g.delay.size() > shown)
        print_bullet("... and " + std::to_string(g.delay.size() - shown) + " more");
    }
  }
}

void print_got_report(const extractor::got_result_t& r) {
  if (r.entries.empty()) { console::info("no GOT entries"); return; }

  print_section("GOT summary (" + r.format + " / " + r.architecture + ")");
  std::ostringstream counts;
  counts << r.slot_count << " slots"
         << "  |  " << r.named_count << " named"
         << "  |  " << r.plt_count << " PLT/stub";
  if (r.lazy_count > 0) counts << "  |  " << r.lazy_count << " lazy";
  print_kv_colored("Entries", counts.str(), console::green);
  if (r.got_lowest_slot != 0 || r.got_highest_slot != 0) {
    print_kv("Slot range",
             hex_rva(r.got_lowest_slot) + " .. " + hex_rva(r.got_highest_slot));
  }
  if (!r.sections.empty()) {
    std::string secs;
    for (const auto& s : r.sections) {
      if (!secs.empty()) secs += ", ";
      secs += s;
    }
    print_kv("Sections", secs);
  }
  if (r.truncated) print_kv_colored("Truncated", "yes", console::yellow);

  constexpr std::size_t kMaxShown = 40;
  std::size_t shown = 0;
  for (const auto& e : r.entries) {
    if (shown++ >= kMaxShown) break;
    std::ostringstream line;
    line << "slot=" << hex_value(e.slot_address);
    if (e.plt_stub_address) line << "  plt=" << hex_value(e.plt_stub_address);
    if (e.stub_address)     line << "  stub=" << hex_value(e.stub_address);
    if (!e.reloc_type.empty()) line << "  " << e.reloc_type;
    line << "  ";
    if (e.name.empty()) line << "(anonymous)";
    else                line << e.name;
    if (!e.library.empty()) line << "  <" << e.library << ">";
    if (e.is_lazy) line << "  [lazy]";
    if (e.is_weak) line << "  [weak]";
    print_bullet(line.str());
  }
  if (r.entries.size() > shown)
    print_bullet("... and " + std::to_string(r.entries.size() - shown) + " more");
}

// ---------------------------------------------------------------------------
// IAT/GOT call-site rendering
// ---------------------------------------------------------------------------

void print_xref_asm_report(const r2::xref_asm_result_t& r) {
  const bool okish = (r.st == r2::status::ok) || (r.st == r2::status::partial);
  if (!okish) {
    if (r.st == r2::status::bad_output && r.xrefs_found == 0) {
      console::info("no call sites found for the supplied IAT/GOT slots");
      return;
    }
    console::error(std::string("iat/got call-site asm: ") + r2::to_string(r.st));
    if (!r.error.empty()) console::error("  " + r.error);
    for (const auto& [k, v] : r.errors) console::error("  [" + k + "] " + v);
    return;
  }

  print_section("IAT/GOT call-site assembly");
  {
    std::string_view color =
        (r.st == r2::status::ok) ? console::green : console::yellow;
    print_kv_colored("Status", r2::to_string(r.st), color);
  }
  print_kv("Slots queried",   std::to_string(r.slots_input));
  print_kv("Slots w/ xrefs",  std::to_string(r.slots_with_xrefs));
  print_kv_colored("Call sites", std::to_string(r.xrefs_found), console::green);
  print_kv_colored("Functions",  std::to_string(r.functions_dumped), console::green);
  if (r.instructions_total > 0) {
    print_kv("Instructions", std::to_string(r.instructions_total));
  }
  if (r.functions_truncated > 0) {
    print_kv_colored("Truncated", std::to_string(r.functions_truncated) + " function(s)",
                     console::yellow);
  }
  if (!r.path.empty())      print_kv("Output", r.path);
  if (r.bytes > 0)          print_kv("Size", std::to_string(r.bytes) + " bytes");
  if (!r.json_path.empty()) print_kv("Raw JSON", r.json_path);

  if (!r.errors.empty()) {
    print_section("IAT/GOT call-site warnings");
    for (const auto& [k, v] : r.errors) {
      print_bullet("[" + k + "] " + v, console::yellow);
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers for the xref target collection
// ---------------------------------------------------------------------------

bool collect_xref_targets(const analyzer::file_info_t& info,
                          bool is_pe, bool is_elf, bool is_macho,
                          std::uint64_t pe_image_base,
                          std::vector<std::uint64_t>& out) {
  out.clear();

  if (is_pe) {
    extractor::iat_result_t iat{};
    if (!extractor::extract_iat(iat, info)) return false;

    std::uint64_t image_base = pe_image_base;
    if (image_base == 0) {
      image_base = 0x140000000ull;
      print_warn("PE image base not reported by rabin2; assuming 0x140000000");
    }
    LOG_INFO("r2: xref targets: using PE image base {}", hex_value(image_base));

    for (const auto& e : iat.entries) {
      if (e.iat_rva == 0) continue;
      out.push_back(image_base + e.iat_rva);
    }
    return !out.empty();
  }

  if (is_elf || is_macho) {
    extractor::got_result_t got{};
    if (!extractor::extract_got(got, info)) return false;
    for (const auto& e : got.entries) {
      if (e.slot_address == 0) continue;
      out.push_back(e.slot_address);
    }
    return !out.empty();
  }

  return false;
}
