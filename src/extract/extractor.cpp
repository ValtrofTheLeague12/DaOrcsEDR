#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>

#include "extractor.hpp"
#include "file_hasher.hpp"
#include "logging.hpp"
#include "yara_scanner.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#if defined(__GNUC__) && defined(__has_attribute) && __has_attribute(no_instrument_function)
#define EXTRACTOR_NO_INSTRUMENT __attribute__((no_instrument_function))
#else
#define EXTRACTOR_NO_INSTRUMENT
#endif

namespace extractor {

namespace {

using clock_type = std::chrono::steady_clock;

double seconds_since(clock_type::time_point start) {
  return std::chrono::duration<double>(clock_type::now() - start).count();
}

const char* error_name(extractor_error error) {
  switch (error) {
    case extractor_error::none:               return "none";
    case extractor_error::invalid_input:      return "invalid_input";
    case extractor_error::invalid_path:       return "invalid_path";
    case extractor_error::empty_file:         return "empty_file";
    case extractor_error::read_failed:        return "read_failed";
    case extractor_error::parse_failed:       return "parse_failed";
    case extractor_error::capstone_failed:    return "capstone_failed";
    case extractor_error::unsupported_format: return "unsupported_format";
    case extractor_error::no_code_section:    return "no_code_section";
    case extractor_error::no_strings:         return "no_strings";
    case extractor_error::no_debug_symbols:   return "no_debug_symbols";
    case extractor_error::hash_failed:        return "hash_failed";
    case extractor_error::no_signature:       return "no_signature";
    case extractor_error::no_guards:          return "no_guards";
    case extractor_error::capa_not_found:     return "capa_not_found";
    case extractor_error::capa_failed:        return "capa_failed";
    case extractor_error::capa_timeout:       return "capa_timeout";
    case extractor_error::hexdump_read_failed: return "hexdump_read_failed";
    case extractor_error::cminer_not_found:   return "cminer_not_found";
    case extractor_error::cminer_failed:      return "cminer_failed";
    case extractor_error::cminer_timeout:     return "cminer_timeout";
  }
  return "unknown";
}

extractor_error map_analyzer_error(const analyzer::file_info_t& info) {
  if (analyzer::has_error(info.errors.flags, analyzer::file_error::invalid_path))
    return extractor_error::invalid_path;
  if (analyzer::has_error(info.errors.flags, analyzer::file_error::empty_file))
    return extractor_error::empty_file;
  if (analyzer::has_error(info.errors.flags, analyzer::file_error::read_failed))
    return extractor_error::read_failed;
  if (analyzer::has_error(info.errors.flags, analyzer::file_error::parse_failed))
    return extractor_error::parse_failed;
  return extractor_error::invalid_input;
}

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

EXTRACTOR_NO_INSTRUMENT bool is_string_char(std::uint8_t c) {
  return (c >= 0x20 && c < 0x7F) || c == '\t';
}

// ---------------------------------------------------------------------------
// Section classification
// ---------------------------------------------------------------------------

struct perms_t {
  bool readable   = false;
  bool writable   = false;
  bool executable = false;
};

perms_t perms_of(LIEF::Section* section) {
  perms_t p;
  if (auto* pe = dynamic_cast<LIEF::PE::Section*>(section)) {
    for (LIEF::PE::Section::CHARACTERISTICS flag : pe->characteristics_list()) {
      if (flag == LIEF::PE::Section::CHARACTERISTICS::MEM_READ) p.readable = true;
      if (flag == LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE) p.writable = true;
      if (flag == LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE) p.executable = true;
    }
    return p;
  }
  if (auto* elf = dynamic_cast<LIEF::ELF::Section*>(section)) {
    p.readable = elf->has(LIEF::ELF::Section::FLAGS::ALLOC);
    p.writable = elf->has(LIEF::ELF::Section::FLAGS::WRITE);
    p.executable = elf->has(LIEF::ELF::Section::FLAGS::EXECINSTR);
    return p;
  }
  if (auto* macho = dynamic_cast<LIEF::MachO::Section*>(section)) {
    const std::string name = lower(macho->name());
    p.executable = name == "__text" || name == "__stubs" || name == "__stub_helper";
    p.readable = name == "__cstring"       || name == "__const"          ||
                 name == "__text"          || name == "__data"           ||
                 name == "__objc_methname" || name == "__objc_classname" ||
                 name == "__objc_methtype" || name == "__info_plist"     ||
                 name == "__oslog"         || name == "__ustring";
    return p;
  }
  return p;
}

bool is_code_section(LIEF::Section* section) { return perms_of(section).executable; }
bool is_readable_section(LIEF::Section* section) { return perms_of(section).readable; }

// Known packer names
struct packer_name_t {
  const char* name;
  const char* family;
};

const packer_name_t* find_packer_name(const std::string& name) {
  static constexpr packer_name_t PACKER_NAMES[] = {
      {"upx0", "UPX"},        {"upx1", "UPX"},       {"upx2", "UPX"},       {"upx3", "UPX"},
      {".upx", "UPX"},        {"packed", nullptr},   {".packed", nullptr},  {"petite", "Petite"},
      {".petite", "Petite"},  {".aspack", "ASPack"}, {"aspack", "ASPack"},  {".adata", "ASPack"},
      {"enigma1", "Enigma"},  {"enigma2", "Enigma"}, {".enigma1", "Enigma"}, {".enigma2", "Enigma"},
      {".vmp0", "VMProtect"}, {".vmp1", "VMProtect"}, {".vmp2", "VMProtect"}, {"vmp0", "VMProtect"},
      {"vmp1", "VMProtect"},  {"vmp2", "VMProtect"}, {".themida", "Themida"}, {".nsp0", "NsPack"},
      {".nsp1", "NsPack"},    {".nsp2", "NsPack"},   {".neolit", "Neolite"}, {"neolit", "Neolite"},
      {".bzz", nullptr},      {".mpress1", "MPRESS"}, {".mpress2", "MPRESS"}, {".psm", nullptr},
      {"tbx", nullptr},       {"tsx", nullptr},      {"ntadata", nullptr},  {".sforce3", nullptr},
      {".sfx", nullptr},      {".pesec", nullptr},   {"pefmt", nullptr},
  };
  const std::string lowered = lower(name);
  for (const packer_name_t& entry : PACKER_NAMES) {
    if (lowered == entry.name) return &entry;
  }
  return nullptr;
}

bool is_debug_section_name(const std::string& name) {
  const std::string lowered = lower(name);
  static constexpr const char* DEBUG_PREFIXES[] = {
      ".debug", ".symtab", ".strtab", ".stab", ".gdb_index",
      ".line", ".sframe", ".zdebug",
  };
  for (const char* prefix : DEBUG_PREFIXES) {
    if (lowered.rfind(prefix, 0) == 0) return true;
  }
  return lowered == "debug" || lowered == ".gnu_debuglink" || lowered == ".gnu_debugaltlink";
}

// ---------------------------------------------------------------------------
// Architecture helpers (LIEF version tolerant)
// ---------------------------------------------------------------------------

// Returns the abstract (format-agnostic) header for any LIEF binary.
LIEF::Header abstract_header(LIEF::Binary& binary) {
  return binary.header();
}

bool resolve_capstone_arch(const LIEF::Header& header, cs_arch& arch, cs_mode& mode,
                           std::string& architecture_name) {
  architecture_name = LIEF::to_string(header.architecture());
  mode = header.endianness() == LIEF::Header::ENDIANNESS::BIG
             ? static_cast<cs_mode>(CS_MODE_BIG_ENDIAN)
             : CS_MODE_LITTLE_ENDIAN;

  switch (header.architecture()) {
    case LIEF::Header::ARCHITECTURES::X86:
    case LIEF::Header::ARCHITECTURES::X86_64:
      arch = CS_ARCH_X86;
      if (header.is_64()) mode = static_cast<cs_mode>(mode | CS_MODE_64);
      else if (header.is_32()) mode = static_cast<cs_mode>(mode | CS_MODE_32);
      else mode = static_cast<cs_mode>(mode | CS_MODE_16);
      return true;
    case LIEF::Header::ARCHITECTURES::ARM64:
      arch = CS_ARCH_ARM64;
      mode = static_cast<cs_mode>(mode | CS_MODE_ARM);
      return true;
    case LIEF::Header::ARCHITECTURES::ARM:
      arch = CS_ARCH_ARM;
      mode = static_cast<cs_mode>(
          mode | (header.is(LIEF::Header::MODES::THUMB) ? CS_MODE_THUMB : CS_MODE_ARM));
      return true;
    case LIEF::Header::ARCHITECTURES::MIPS:
      arch = CS_ARCH_MIPS;
      mode = static_cast<cs_mode>(mode | (header.is_32() ? CS_MODE_MIPS32 : CS_MODE_MIPS64));
      return true;
    case LIEF::Header::ARCHITECTURES::PPC:
    case LIEF::Header::ARCHITECTURES::PPC64:
      arch = CS_ARCH_PPC;
      mode = static_cast<cs_mode>(mode | (header.is_32() ? CS_MODE_32 : CS_MODE_64));
      return true;
    case LIEF::Header::ARCHITECTURES::SPARC:
      arch = CS_ARCH_SPARC;
      if (!header.is_32()) mode = static_cast<cs_mode>(mode | CS_MODE_V9);
      return true;
    case LIEF::Header::ARCHITECTURES::SYSZ:
      arch = CS_ARCH_SYSZ;
      mode = static_cast<cs_mode>(CS_MODE_BIG_ENDIAN);
      return true;
    case LIEF::Header::ARCHITECTURES::RISCV:
#if CS_API_MAJOR >= 5
      arch = CS_ARCH_RISCV;
      mode = static_cast<cs_mode>(mode | (header.is_32() ? CS_MODE_RISCV32 : CS_MODE_RISCV64));
      return true;
#else
      return false;
#endif
    case LIEF::Header::ARCHITECTURES::XCORE:
      arch = CS_ARCH_XCORE;
      mode = CS_MODE_LITTLE_ENDIAN;
      return true;
    case LIEF::Header::ARCHITECTURES::UNKNOWN:
    case LIEF::Header::ARCHITECTURES::LOONGARCH:
    default:
      return false;
  }
}

bool check_file_ok(const analyzer::file_info_t& info, error_type_t& errors) {
  if (info.filepath.empty()) {
    add_error(errors, extractor_error::invalid_input, "Empty file path provided");
    return false;
  }
  if (analyzer::has_errors(info)) {
    const extractor_error mapped = map_analyzer_error(info);
    add_error(errors, mapped, "File rejected by the analyzer: " + info.filepath);
    for (const std::string& message : analyzer::get_error_messages(info)) {
      add_error(errors, mapped, message);
    }
    return false;
  }
  if (info.size == 0) {
    add_error(errors, extractor_error::empty_file,
              "File is empty: " + info.filepath);
    return false;
  }
  return true;
}

std::unique_ptr<LIEF::Binary> load_binary_safe(const std::string& path,
                                               error_type_t& errors) {
  try {
    auto binary = LIEF::Parser::parse(path);
    if (!binary) {
      add_error(errors, extractor_error::parse_failed,
                "LIEF could not parse the file");
      return nullptr;
    }
    return binary;
  } catch (const std::exception& e) {
    add_error(errors, extractor_error::parse_failed, e.what());
    return nullptr;
  }
}

template <class Result, class Fn>
bool with_binary(Result& result, const analyzer::file_info_t& info, Fn&& fn) {
  result = {};
  if (!check_file_ok(info, result.errors)) return false;
  auto binary = load_binary_safe(info.filepath, result.errors);
  if (!binary) return false;
  return fn(*binary);
}

// ---------------------------------------------------------------------------
// ELF GNU Property note parsing
// ---------------------------------------------------------------------------

void parse_gnu_property_note(const LIEF::ELF::Note& note, guard_info_t& out,
                             std::size_t alignment) {
  const LIEF::span<const std::uint8_t> desc = note.description();
  const std::size_t end = desc.size();
  std::size_t off = 0;

  constexpr std::uint32_t GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000u;
  constexpr std::uint32_t GNU_PROPERTY_AARCH64_FEATURE_1_BTI = 1u << 0;
  constexpr std::uint32_t GNU_PROPERTY_AARCH64_FEATURE_1_PAC = 1u << 1;
  constexpr std::uint32_t GNU_PROPERTY_X86_FEATURE_1_AND     = 0xc0000002u;
  constexpr std::uint32_t GNU_PROPERTY_X86_FEATURE_1_IBT     = 1u << 0;
  constexpr std::uint32_t GNU_PROPERTY_X86_FEATURE_1_SHSTK   = 1u << 1;

  while (off + 8 <= end) {
    std::uint32_t pr_type   = 0;
    std::uint32_t pr_datasz = 0;
    std::memcpy(&pr_type,   desc.data() + off,     4);
    std::memcpy(&pr_datasz, desc.data() + off + 4, 4);
    off += 8;

    const std::size_t data_off = off;
    const std::size_t data_end = off + pr_datasz;
    if (data_end > end) break;

    if (pr_type == GNU_PROPERTY_X86_FEATURE_1_AND && pr_datasz >= 4) {
      std::uint32_t bits = 0;
      std::memcpy(&bits, desc.data() + data_off, 4);
      out.x86_features_raw = bits;
      if (bits & GNU_PROPERTY_X86_FEATURE_1_IBT) {
        out.has_ibt = true;
        out.notes.push_back("GNU_PROPERTY X86_FEATURE_1_IBT");
      }
      if (bits & GNU_PROPERTY_X86_FEATURE_1_SHSTK) {
        out.has_shstk = true;
        out.notes.push_back("GNU_PROPERTY X86_FEATURE_1_SHSTK");
      }
    } else if (pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND && pr_datasz >= 4) {
      std::uint32_t bits = 0;
      std::memcpy(&bits, desc.data() + data_off, 4);
      out.aarch64_features_raw = bits;
      if (bits & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) {
        out.has_bti = true;
        out.notes.push_back("GNU_PROPERTY AARCH64_FEATURE_1_BTI");
      }
      if (bits & GNU_PROPERTY_AARCH64_FEATURE_1_PAC) {
        out.has_pac = true;
        out.notes.push_back("GNU_PROPERTY AARCH64_FEATURE_1_PAC");
      }
    }

    off = (data_end + (alignment - 1)) & ~(alignment - 1);
  }
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

bool guard_impl(guard_info_t& result, LIEF::Binary& binary) {
  auto tally = [&result](bool enabled) {
    ++result.mitigations_checked;
    if (enabled) ++result.mitigations_enabled;
  };
  auto note_if = [&result](bool cond, const char* msg) {
    if (cond) result.notes.push_back(msg);
  };

  if (auto* pe = dynamic_cast<LIEF::PE::Binary*>(&binary)) {
    result.format = "PE";

    const LIEF::PE::OptionalHeader& opt = pe->optional_header();
    result.dll_characteristics_raw =
        static_cast<std::uint16_t>(opt.dll_characteristics());

    using DC = LIEF::PE::OptionalHeader::DLL_CHARACTERISTICS;
    auto has = [&opt](DC flag) { return opt.has(flag); };

    result.has_aslr            = has(DC::DYNAMIC_BASE);
    result.has_high_entropy_va = has(DC::HIGH_ENTROPY_VA);
    result.has_dep             = has(DC::NX_COMPAT);
    result.has_nx              = has(DC::NX_COMPAT);
    result.has_force_integrity = has(DC::FORCE_INTEGRITY);
    result.has_isolation       = !has(DC::NO_ISOLATION);
    result.has_seh             = !has(DC::NO_SEH);
    result.has_no_bind         = has(DC::NO_BIND);
    result.has_wdm_driver      = has(DC::WDM_DRIVER);
    result.has_guard_cf        = has(DC::GUARD_CF);

    if (const LIEF::PE::LoadConfiguration* load_config = pe->load_configuration()) {
      result.has_stack_cookie = load_config->security_cookie() != 0;
      const auto handler_count = load_config->se_handler_count();
      result.has_safe_seh = handler_count.has_value() && *handler_count > 0;
    }

    for (const LIEF::PE::Debug& debug : pe->debug()) {
      if (const auto* ex = dynamic_cast<const LIEF::PE::ExDllCharacteristics*>(&debug)) {
        using EX = LIEF::PE::ExDllCharacteristics::CHARACTERISTICS;
        result.has_cet_compat = ex->has(EX::CET_COMPAT);
        result.cet_strict_mode = ex->has(EX::CET_COMPAT_STRICT_MODE);
        result.cet_set_context_ip_validation_relaxed =
            ex->has(EX::CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE);
        result.cet_dynamic_apis_allow_in_proc = ex->has(EX::CET_DYNAMIC_APIS_ALLOW_IN_PROC);
      }
    }

    tally(result.has_aslr);
    tally(result.has_dep);
    tally(result.has_high_entropy_va);
    tally(result.has_guard_cf);
    tally(result.has_stack_cookie);
    tally(result.has_cet_compat);

    note_if(result.has_aslr,            "ASLR enabled (DYNAMIC_BASE)");
    note_if(result.has_dep,             "DEP enabled (NX_COMPAT)");
    note_if(result.has_high_entropy_va, "High-entropy VA");
    note_if(result.has_force_integrity, "Force Integrity");
    note_if(result.has_seh,             "SEH enabled");
    note_if(!result.has_isolation,      "Isolation disabled (NO_ISOLATION)");
    note_if(result.has_guard_cf,        "Control Flow Guard (CFG)");
    note_if(result.has_wdm_driver,      "WDM driver");
    note_if(result.has_stack_cookie,    "Stack cookie (/GS)");
    note_if(result.has_safe_seh,        "SafeSEH handler table");
    note_if(result.has_cet_compat,      "CET compatible");
    note_if(result.cet_strict_mode,     "CET strict mode");

    if (result.mitigations_enabled == 0) {
      add_error(result.errors, extractor_error::no_guards,
                "PE has none of ASLR, DEP, CFG, /GS or CET enabled");
    }
    return true;
  }

  if (auto* elf = dynamic_cast<LIEF::ELF::Binary*>(&binary)) {
    result.format = "ELF";

    result.has_pie = elf->is_pie();
    result.has_aslr = result.has_pie;
    result.has_nx = elf->has_nx();
    result.has_dep = result.has_nx;
    result.executable_stack = !result.has_nx;
    result.has_relro = elf->has(LIEF::ELF::Segment::TYPE::GNU_RELRO);

    bool bind_now = elf->has(LIEF::ELF::DynamicEntry::TAG::BIND_NOW);
    for (const LIEF::ELF::DynamicEntry& entry : elf->dynamic_entries()) {
      const auto tag = entry.tag();
      if (tag == LIEF::ELF::DynamicEntry::TAG::FLAGS ||
          tag == LIEF::ELF::DynamicEntry::TAG::FLAGS_1) {
        if (const auto* flags = dynamic_cast<const LIEF::ELF::DynamicEntryFlags*>(&entry)) {
          using FLAG = LIEF::ELF::DynamicEntryFlags::FLAG;
          if (flags->has(FLAG::BIND_NOW) || flags->has(FLAG::NOW)) bind_now = true;
        }
      }
    }
    result.has_full_relro = result.has_relro && bind_now;
    result.has_rpath = elf->has(LIEF::ELF::DynamicEntry::TAG::RPATH) ||
                       elf->has(LIEF::ELF::DynamicEntry::TAG::RUNPATH);

    auto scan_symbol = [&result](const LIEF::ELF::Symbol& symbol) {
      const std::string& name = symbol.name();
      if (name == "__stack_chk_fail" || name == "__stack_chk_guard") {
        result.has_stack_canary = true;
      } else if (name.size() > 6 && name.rfind("__", 0) == 0 &&
                 name.compare(name.size() - 4, 4, "_chk") == 0) {
        result.has_fortify = true;
      }
    };
    for (const LIEF::ELF::Symbol& symbol : elf->dynamic_symbols()) {
      if (symbol.is_imported()) scan_symbol(symbol);
    }
    if (!result.has_stack_canary || !result.has_fortify) {
      for (const LIEF::ELF::Symbol& symbol : elf->symtab_symbols()) scan_symbol(symbol);
    }

    const std::size_t alignment =
        elf->header().identity_class() == LIEF::ELF::Header::CLASS::ELF32 ? 4 : 8;
    for (const LIEF::ELF::Note& note : elf->notes()) {
      if (note.name() != "GNU") continue;
      if (note.type() != LIEF::ELF::Note::TYPE::GNU_PROPERTY_TYPE_0) continue;
      parse_gnu_property_note(note, result, alignment);
    }

    tally(result.has_pie);
    tally(result.has_nx);
    tally(result.has_full_relro);
    tally(result.has_stack_canary);
    tally(result.has_fortify);
    if (result.aarch64_features_raw != 0 || result.has_bti || result.has_pac) {
      tally(result.has_bti);
      tally(result.has_pac);
    } else {
      tally(result.has_ibt);
      tally(result.has_shstk);
    }

    note_if(result.has_pie,          "PIE (position independent executable)");
    note_if(result.has_nx,           "NX stack (GNU_STACK not executable)");
    note_if(result.executable_stack, "Executable stack");
    note_if(result.has_relro && !result.has_full_relro, "Partial RELRO");
    note_if(result.has_full_relro,   "Full RELRO (RELRO + BIND_NOW)");
    note_if(result.has_stack_canary, "Stack canary (__stack_chk_fail)");
    note_if(result.has_fortify,      "FORTIFY_SOURCE (__*_chk imports)");
    note_if(result.has_rpath,        "RPATH/RUNPATH set");

    if (result.mitigations_enabled == 0) {
      add_error(result.errors, extractor_error::no_guards,
                "ELF has no PIE, NX, RELRO, canary, FORTIFY or CET/BTI/PAC protections");
    }
    return true;
  }

  if (dynamic_cast<LIEF::MachO::Binary*>(&binary)) {
    result.format = "MachO";
    result.has_pie = binary.is_pie();
    result.has_aslr = result.has_pie;
    result.has_nx = binary.has_nx();
    result.has_dep = result.has_nx;
    result.executable_stack = !result.has_nx;
    for (const LIEF::Symbol& symbol : binary.symbols()) {
      const std::string& name = symbol.name();
      if (name == "___stack_chk_fail" || name == "___stack_chk_guard") {
        result.has_stack_canary = true;
        break;
      }
    }
    tally(result.has_pie);
    tally(result.has_nx);
    tally(result.has_stack_canary);
    note_if(result.has_pie,          "PIE");
    note_if(result.has_nx,           "Non-executable stack");
    note_if(result.has_stack_canary, "Stack canary (___stack_chk_fail)");

    if (result.mitigations_enabled == 0) {
      add_error(result.errors, extractor_error::no_guards,
                "Mach-O has no PIE, NX stack or stack canary");
    }
    return true;
  }

  result.format = "Unknown";
  add_error(result.errors, extractor_error::unsupported_format,
            "Guard extraction not supported for this format");
  return false;
}

void fill_section_common(const LIEF::Section& section, LIEF::Section* mutable_section,
                         std::uint64_t& size, double& entropy, double& chi2,
                         file_hash_t& sha256, fuzzy_hash_t& tlsh, bool& readable,
                         bool& writable, bool& executable) {
  const LIEF::span<const std::uint8_t> content = section.content();
  size = content.size();
  entropy = calculate_entropy(content.data(), content.size());
  chi2 = calculate_chi2(content.data(), content.size());
  hasher::hash_bytes(sha256, content.data(), content.size());
  hasher::fuzzy_hash_bytes(tlsh, content.data(), content.size());
  const perms_t perms = perms_of(mutable_section);
  readable = perms.readable;
  writable = perms.writable;
  executable = perms.executable;
}



bool got_elf_impl(got_result_t& result, LIEF::ELF::Binary& elf,
                  const std::string& path, std::size_t max_entries) {
  result.format = "ELF";

 
  result.architecture = LIEF::to_string(
      static_cast<LIEF::Binary&>(elf).header().architecture());

  auto section_of = [&](std::uint64_t va) -> const LIEF::ELF::Section* {
    for (const auto& s : elf.sections()) {
      const std::uint64_t start = s.virtual_address();
      const std::uint64_t end   = start + s.size();
      if (va >= start && va < end) return &s;
    }
    return nullptr;
  };

  auto push_entry = [&result, max_entries](got_entry_t&& e) {
    if (result.entries.size() >= max_entries) { result.truncated = true; return; }
    if (result.got_lowest_slot == 0 || e.slot_address < result.got_lowest_slot)
      result.got_lowest_slot = e.slot_address;
    if (e.slot_address > result.got_highest_slot)
      result.got_highest_slot = e.slot_address;
    result.entries.push_back(std::move(e));
  };

  static constexpr const char* kGotSections[] = {
      ".got", ".got.plt", ".got.sec", ".plt", ".plt.got", ".plt.sec",
      ".iplt", ".igot", ".igot.plt",
  };
  std::unordered_set<std::string> seen_sections;
  for (const auto& s : elf.sections()) {
    const std::string name = s.name();
    for (const char* candidate : kGotSections) {
      if (name == candidate && seen_sections.insert(name).second) {
        result.sections.push_back(name);
      }
    }
  }

  for (const LIEF::ELF::Relocation& rel : elf.relocations()) {
    const std::uint64_t slot_va = rel.address();
    const LIEF::ELF::Section* sec = section_of(slot_va);
    if (sec == nullptr) continue;

    const std::string sec_name = sec->name();
    bool in_got = false;
    for (const char* candidate : kGotSections) {
      if (sec_name == candidate) { in_got = true; break; }
    }
    if (!in_got) continue;

    got_entry_t e{};
    e.slot_address  = slot_va;
    e.slot_offset   = sec->offset() + (slot_va - sec->virtual_address());
    e.reloc_address = slot_va;
    e.reloc_type    = LIEF::ELF::to_string(rel.type());
    e.reloc_addend  = rel.addend();

    if (const LIEF::ELF::Symbol* sym = rel.symbol()) {
      e.name     = sym->name();
      e.binding  = LIEF::ELF::to_string(sym->binding());
      e.is_weak  = sym->binding() == LIEF::ELF::Symbol::BINDING::WEAK;
      ++result.named_count;
    }

    try {
      const auto content = sec->content();
      const std::size_t rel_off =
          static_cast<std::size_t>(slot_va - sec->virtual_address());
      if (rel_off + 8 <= content.size()) {
        std::uint64_t v = 0;
        std::memcpy(&v, content.data() + rel_off, 8);
        e.initial_value = v;
      }
    } catch (...) {}

    ++result.slot_count;
    push_entry(std::move(e));
    if (result.truncated) break;
  }

  // Fallback: PLT section scan for stripped binaries without dynamic relocations.
  if (result.entries.empty()) {
    static constexpr const char* kPltSections[] = {".plt", ".plt.sec", ".plt.got"};
    for (const auto& s : elf.sections()) {
      bool is_plt = false;
      for (const char* candidate : kPltSections) {
        if (s.name() == candidate) { is_plt = true; break; }
      }
      if (!is_plt) continue;

      const auto content = s.content();
      const std::size_t stride = 16;
      const std::size_t count = content.size() / stride;

      for (std::size_t i = 0; i < count && !result.truncated; ++i) {
        got_entry_t e{};
        e.plt_stub_address = s.virtual_address() + i * stride;
        ++result.plt_count;
        push_entry(std::move(e));
      }
      break;
    }
  }

  LOG_INFO("extractor: got_elf_impl: '{}' — {} slots ({} named, {} PLT)",
           path, result.slot_count, result.named_count, result.plt_count);

  if (result.entries.empty()) {
    add_error(result.errors, extractor_error::no_code_section,
              "No GOT/PLT entries found in ELF");
    return false;
  }
  return true;
}

bool got_macho_impl(got_result_t& result, LIEF::MachO::Binary& macho,
                    const std::string& path, std::size_t max_entries) {
  result.format = "MachO";

  // MachO::Header has no to_string() overload; use the abstract Header.
  result.architecture = LIEF::to_string(
      static_cast<LIEF::Binary&>(macho).header().architecture());

  auto push_entry = [&result, max_entries](got_entry_t&& e) {
    if (result.entries.size() >= max_entries) { result.truncated = true; return; }
    if (result.got_lowest_slot == 0 || e.slot_address < result.got_lowest_slot)
      result.got_lowest_slot = e.slot_address;
    if (e.slot_address > result.got_highest_slot)
      result.got_highest_slot = e.slot_address;
    result.entries.push_back(std::move(e));
  };

  static constexpr const char* kGotSections[] = {
      "__got", "__la_symbol_ptr", "__nl_symbol_ptr",
  };
  static constexpr const char* kStubSections[] = { "__stubs", "__stub_helper" };

  std::unordered_set<std::string> seen_sections;
  for (const auto& s : macho.sections()) {
    const std::string name = s.name();
    for (const char* c : kGotSections) {
      if (name == c && seen_sections.insert(name).second)
        result.sections.push_back(name);
    }
  }

  auto section_of = [&](std::uint64_t va) -> const LIEF::MachO::Section* {
    for (const auto& s : macho.sections()) {
      if (va >= s.virtual_address() &&
          va <  s.virtual_address() + s.size()) {
        return &s;
      }
    }
    return nullptr;
  };

  try {
    for (const LIEF::MachO::BindingInfo& bind : macho.bindings()) {
      got_entry_t e{};
      e.slot_address = bind.address();
      e.name         = bind.symbol() ? bind.symbol()->name() : std::string();
      e.library      = bind.library() ? bind.library()->name() : std::string();
      e.is_weak      = bind.is_weak_import();
      e.binding      = e.is_weak ? "WEAK" : "GLOBAL";

      // Lazy-ness from section membership (__la_symbol_ptr is the lazy table).
      // No portable BindingInfo::binding_class() exists across LIEF versions.
      if (const auto* sec = section_of(e.slot_address)) {
        e.slot_offset = sec->offset() + (e.slot_address - sec->virtual_address());
        if (std::string(sec->name()) == "__la_symbol_ptr") e.is_lazy = true;
      }

      if (!e.name.empty()) ++result.named_count;
      if (e.is_lazy)       ++result.lazy_count;

      ++result.slot_count;
      push_entry(std::move(e));
      if (result.truncated) break;
    }
  } catch (const std::exception& ex) {
    LOG_DEBUG("extractor: got_macho_impl: bindings() unavailable ({})", ex.what());
  }

  if (result.entries.empty()) {
    // MachO::Header has no is_64(); infer pointer width from CPU type.
    using CPU = LIEF::MachO::Header::CPU_TYPE;
    const CPU cpu = macho.header().cpu_type();
    const bool is_64 = cpu == CPU::X86_64 || cpu == CPU::ARM64 ||
                       cpu == CPU::POWERPC64 || cpu == CPU::ARM64;
    const std::size_t pointer_size = is_64 ? 8 : 4;

    for (const auto& s : macho.sections()) {
      bool is_got = false;
      for (const char* c : kGotSections) {
        if (s.name() == c) { is_got = true; break; }
      }
      if (!is_got) continue;

      const auto content = s.content();
      const std::size_t count = content.size() / pointer_size;

      for (std::size_t i = 0; i < count && !result.truncated; ++i) {
        got_entry_t e{};
        e.slot_address = s.virtual_address() + i * pointer_size;
        e.slot_offset  = s.offset() + i * pointer_size;
        e.is_lazy      = (s.name() == "__la_symbol_ptr");
        if (e.is_lazy) ++result.lazy_count;
        ++result.slot_count;

        std::uint64_t v = 0;
        const std::size_t copy =
            std::min<std::size_t>(pointer_size, content.size() - i * pointer_size);
        std::memcpy(&v, content.data() + i * pointer_size, copy);
        e.initial_value = v;
        push_entry(std::move(e));
      }
      break;
    }
  }

  for (const auto& s : macho.sections()) {
    for (const char* c : kStubSections) {
      if (s.name() == c) { ++result.plt_count; break; }
    }
  }

  LOG_INFO("extractor: got_macho_impl: '{}' — {} slots ({} named, {} lazy)",
           path, result.slot_count, result.named_count, result.lazy_count);

  if (result.entries.empty()) {
    add_error(result.errors, extractor_error::no_code_section,
              "No GOT / lazy pointer entries found in Mach-O");
    return false;
  }
  return true;
}

bool got_impl(got_result_t& result, LIEF::Binary& binary,
              const std::string& path, std::size_t max_entries) {
  if (auto* elf = dynamic_cast<LIEF::ELF::Binary*>(&binary))
    return got_elf_impl(result, *elf, path, max_entries);
  if (auto* macho = dynamic_cast<LIEF::MachO::Binary*>(&binary))
    return got_macho_impl(result, *macho, path, max_entries);
  return true;
}

// ---------------------------------------------------------------------------
// ELF sections
// ---------------------------------------------------------------------------

bool elf_impl(elf_sections_t& result, LIEF::Binary& binary, const std::string& path) {
  auto* elf = dynamic_cast<LIEF::ELF::Binary*>(&binary);
  if (elf == nullptr) {
    add_error(result.errors, extractor_error::parse_failed,
              "File is not an ELF binary: " + path);
    return false;
  }

  const LIEF::ELF::Header& header = elf->header();
  result.machine = LIEF::ELF::to_string(header.machine_type());
  result.file_type = LIEF::ELF::to_string(header.file_type());
  result.entrypoint = elf->entrypoint();
  result.is_pie = elf->is_pie();
  if (elf->has_interpreter()) result.interpreter = elf->interpreter();

  for (const LIEF::ELF::DynamicEntry& entry : elf->dynamic_entries()) {
    if (const auto* library = dynamic_cast<const LIEF::ELF::DynamicEntryLibrary*>(&entry)) {
      result.needed_libraries.push_back(library->name());
    }
  }

  result.sections.reserve(elf->sections().size());
  for (auto& section : elf->sections()) {
    elf_section_t entry{};
    entry.name = section.name();
    entry.virtual_address = section.virtual_address();
    fill_section_common(section, &section, entry.size, entry.entropy, entry.chi2,
                        entry.sha256, entry.tlsh, entry.readable, entry.writable,
                        entry.executable);

    entry.type = LIEF::ELF::to_string(section.type());
    for (LIEF::ELF::Section::FLAGS flag : section.flags_list()) {
      if (!entry.flags.empty()) entry.flags += ", ";
      entry.flags += LIEF::ELF::to_string(flag);
    }
    if (entry.flags.empty()) entry.flags = "none";

    result.sections.push_back(std::move(entry));
  }

  got_elf_impl(result.got, *elf, path, 200000);

  return true;
}

// ---------------------------------------------------------------------------
// IAT — PE
// ---------------------------------------------------------------------------

bool iat_impl(iat_result_t& result, LIEF::Binary& binary,
              const std::string& path, std::size_t max_entries) {
  auto* pe = dynamic_cast<LIEF::PE::Binary*>(&binary);
  if (pe == nullptr) return true;

  result.image_base = pe->optional_header().imagebase();

  auto push_entry = [&result, max_entries](iat_entry_t&& e) {
    if (result.entries.size() >= max_entries) { result.truncated = true; return; }
    if (result.iat_lowest_rva == 0 || e.iat_rva < result.iat_lowest_rva)
      result.iat_lowest_rva = e.iat_rva;
    if (e.iat_rva > result.iat_highest_rva)
      result.iat_highest_rva = e.iat_rva;
    result.entries.push_back(std::move(e));
  };

  for (const LIEF::PE::Import& imp : pe->imports()) {
    ++result.dll_count;
    const std::string  dll_name  = imp.name();
    const std::uint64_t iat_base = imp.import_address_table_rva();
    const std::uint64_t ilt_base = imp.import_lookup_table_rva();
    const std::uint32_t ts       = imp.timedatestamp();
    const std::uint32_t fwd      = imp.forwarder_chain();

    for (const LIEF::PE::ImportEntry& entry : imp.entries()) {
      iat_entry_t e{};
      e.dll        = dll_name;
      e.name       = entry.name();
      e.hint       = entry.hint();
      e.ordinal    = entry.ordinal();
      e.is_ordinal = entry.is_ordinal();
      e.iat_rva    = entry.iat_address();
      try { e.iat_value = entry.iat_value(); } catch (...) {}

      e.ilt_rva    = ilt_base;
      e.iat_base   = iat_base;
      e.timestamp  = ts;
      e.forwarder  = fwd;
      e.is_delay   = false;

      if (ilt_base != 0 && iat_base != 0 && e.iat_rva >= iat_base) {
        e.int_rva = ilt_base + (e.iat_rva - iat_base);
      }

      if (e.is_ordinal) ++result.ordinal_import_count;
      else              ++result.named_import_count;

      push_entry(std::move(e));
      if (result.truncated) break;
    }
    if (result.truncated) break;
  }

  for (const LIEF::PE::DelayImport& dimp : pe->delay_imports()) {
    ++result.delay_dll_count;
    const std::string dll_name = dimp.name();

    for (const LIEF::PE::DelayImportEntry& entry : dimp.entries()) {
      ++result.delay_import_count;
      iat_entry_t e{};
      e.dll        = dll_name;
      e.name       = entry.name();
      e.hint       = entry.hint();
      e.ordinal    = entry.ordinal();
      e.is_ordinal = entry.is_ordinal();
      try { e.iat_value = entry.value(); } catch (...) {}
      e.is_delay = true;

      if (e.is_ordinal) ++result.ordinal_import_count;
      else              ++result.named_import_count;

      push_entry(std::move(e));
      if (result.truncated) break;
    }
    if (result.truncated) break;
  }

  LOG_INFO("extractor: iat_impl: '{}' — {} DLLs, {} named, {} ordinal, "
           "{} delay DLLs, {} delay imports, entries={}",
           path, result.dll_count, result.named_import_count,
           result.ordinal_import_count, result.delay_dll_count,
           result.delay_import_count, result.entries.size());
  return true;
}

// ---------------------------------------------------------------------------
// PE sections
// ---------------------------------------------------------------------------

void scan_pe_overlay(pe_overlay_t& result, const std::string& path,
                     std::uint64_t start, std::uint64_t size);

bool pe_impl(pe_sections_t& result, LIEF::Binary& binary, const std::string& path) {
  auto* pe = dynamic_cast<LIEF::PE::Binary*>(&binary);
  if (pe == nullptr) {
    add_error(result.errors, extractor_error::parse_failed,
              "File is not a PE binary: " + path);
    return false;
  }

  const LIEF::PE::Header& header = pe->header();
  result.machine = LIEF::PE::to_string(header.machine());
  result.characteristics =
      "0x" + [&header]() {
        std::array<char, 16> buffer{};
        std::snprintf(buffer.data(), buffer.size(), "%08X", header.characteristics());
        return std::string(buffer.data());
      }();
  result.entrypoint = pe->entrypoint();
  result.timestamp = header.time_date_stamp();
  result.is_dll = (static_cast<std::uint32_t>(header.characteristics()) & 0x2000u) != 0;
  result.subsystem = LIEF::PE::to_string(pe->optional_header().subsystem());
  result.overlay_size = pe->overlay().size();
  result.file_size = std::filesystem::file_size(path);
  if (const LIEF::PE::DataDirectory* cert_dir = pe->cert_dir()) {
    result.security_directory.present = cert_dir->size() != 0;
    result.security_directory.file_offset = cert_dir->RVA();
    result.security_directory.size = cert_dir->size();
    if (result.security_directory.file_offset <=
            result.file_size &&
        result.security_directory.size <=
            result.file_size - result.security_directory.file_offset) {
      result.security_directory.end_offset =
          result.security_directory.file_offset + result.security_directory.size;
      result.security_directory.within_file = true;
      result.security_directory.valid_range = true;
      std::ifstream cert_input(path, std::ios::binary);
      if (cert_input) {
        cert_input.seekg(static_cast<std::streamoff>(result.security_directory.file_offset));
        std::uint64_t cursor = 0;
        while (cursor + 8 <= result.security_directory.size) {
          std::uint32_t length = 0;
          cert_input.read(reinterpret_cast<char*>(&length), sizeof(length));
          if (!cert_input || length < 8 || length > result.security_directory.size - cursor)
            break;
          ++result.security_directory.certificate_count;
          const std::uint64_t advance = (length + 7u) & ~7u;
          if (advance == 0 || advance > result.security_directory.size - cursor) break;
          cert_input.seekg(static_cast<std::streamoff>(advance - 4), std::ios::cur);
          cursor += advance;
        }
        if (cursor < result.security_directory.size)
          result.security_directory.warnings.push_back(
              "trailing bytes remain in Security Directory range");
      } else {
        result.security_directory.warnings.push_back(
            "could not read Security Directory range");
      }
    } else {
      result.security_directory.warnings.push_back(
          "Security Directory range lies outside the file");
    }
  }
  result.imphash = LIEF::PE::get_imphash(*pe);

  for (const LIEF::PE::Import& import : pe->imports()) {
    result.imported_dlls.push_back(import.name());
    result.import_function_count += import.entries().size();
  }
  if (const LIEF::PE::Export* exports = pe->get_export()) {
    result.export_count = exports->entries().size();
    result.export_table.present = true;
    result.export_table.name = exports->name();
    result.export_table.timestamp = exports->timestamp();
    result.export_table.major_version = exports->major_version();
    result.export_table.minor_version = exports->minor_version();
    result.export_table.ordinal_base = exports->ordinal_base();
    result.export_table.export_addr_table_rva = exports->export_addr_table_rva();
    result.export_table.export_addr_table_count = exports->export_addr_table_cnt();
    result.export_table.names_addr_table_rva = exports->names_addr_table_rva();
    result.export_table.names_addr_table_count = exports->names_addr_table_cnt();
    result.export_table.ordinal_addr_table_rva = exports->ord_addr_table_rva();
    for (const LIEF::PE::ExportEntry& entry : exports->entries()) {
      pe_export_entry_t item{};
      item.name = entry.name();
      item.ordinal = entry.ordinal();
      item.rva = entry.is_extern() ? entry.function_rva() : entry.address();
      item.address = entry.address();
      item.function_rva = entry.function_rva();
      item.is_extern = entry.is_extern();
      item.is_forwarded = entry.is_forwarded();
      if (item.is_forwarded) {
        const auto forward = entry.forward_information();
        item.forwarder_library = forward.library;
        item.forwarder_function = forward.function;
        ++result.export_table.forwarded_count;
      }
      if (item.is_extern) ++result.export_table.external_count;
      if (!item.name.empty()) ++result.export_table.named_count;
      result.export_table.entries.push_back(std::move(item));
    }
  }

  const std::uint64_t entry_rva = pe->optional_header().addressof_entrypoint();

  result.sections.reserve(pe->sections().size());
  for (auto& section : pe->sections()) {
    pe_section_t entry{};
    entry.name = section.name();
    entry.virtual_address = section.virtual_address();
    fill_section_common(section, &section, entry.size, entry.entropy, entry.chi2,
                        entry.sha256, entry.tlsh, entry.readable, entry.writable,
                        entry.executable);

    entry.virtual_size = section.virtual_size();
    entry.raw_size = section.sizeof_raw_data();
    entry.raw_offset = section.offset();
    entry.raw_end = entry.raw_offset + entry.raw_size;
    result.last_section_end = std::max(result.last_section_end, entry.raw_end);
    if (result.security_directory.valid_range &&
        result.security_directory.file_offset < entry.raw_end &&
        result.security_directory.end_offset > entry.raw_offset) {
      result.security_directory.overlaps_section = true;
    }
    for (LIEF::PE::Section::CHARACTERISTICS flag : section.characteristics_list()) {
      if (!entry.characteristics.empty()) entry.characteristics += ", ";
      entry.characteristics += LIEF::PE::to_string(flag);
    }
    if (entry.characteristics.empty()) entry.characteristics = "none";

    const std::uint64_t extent = std::max<std::uint64_t>(entry.virtual_size, entry.raw_size);
    if (result.entry_section.empty() && entry_rva >= entry.virtual_address &&
        entry_rva < entry.virtual_address + extent) {
      result.entry_section = entry.name;
    }

    result.sections.push_back(std::move(entry));
  }

  result.computed_overlay_start = result.last_section_end;
  result.computed_overlay_end = result.file_size;
  result.has_computed_overlay = result.file_size > result.last_section_end;
  result.computed_overlay_size = result.has_computed_overlay
      ? result.file_size - result.last_section_end : 0;
  result.overlay_size_matches = result.computed_overlay_size == result.overlay_size;
  if (result.security_directory.valid_range) {
    result.security_directory.inside_section_overlay =
        result.security_directory.file_offset >= result.last_section_end &&
        result.security_directory.end_offset <= result.file_size;
    if (result.security_directory.inside_section_overlay) {
      const std::uint64_t after = result.file_size - result.security_directory.end_offset;
      result.overlay_after_security_start = result.security_directory.end_offset;
      result.overlay_after_security_end = result.file_size;
      result.overlay_after_security_size = after;
      result.has_overlay_after_security = after > 0;
    }
  }

  if (result.has_computed_overlay) {
    scan_pe_overlay(result.overlay, path, result.computed_overlay_start,
                    result.computed_overlay_size);
  }
  iat_impl(result.iat, binary, path, 200000);
  return true;
}

bool sections_impl(sections_result_t& result, LIEF::Binary& binary) {
  result.sections.reserve(binary.sections().size());
  for (auto& section : binary.sections()) {
    section_info_t entry{};
    entry.name = section.name();
    entry.virtual_address = section.virtual_address();
    const LIEF::span<const std::uint8_t> content = section.content();
    entry.size = content.size();
    entry.entropy = calculate_entropy(content.data(), content.size());
    entry.chi2 = calculate_chi2(content.data(), content.size());
    hasher::hash_bytes(entry.sha256, content.data(), content.size());
    hasher::fuzzy_hash_bytes(entry.tlsh, content.data(), content.size());
    result.sections.push_back(std::move(entry));
  }
  return true;
}

struct overlay_magic_t {
  const char* name;
  const char* description;
  const char* bytes;
  std::size_t length;
  double confidence;
};

// The magics are plain binary literals with explicit lengths. An earlier version
// stored them as escape strings and parsed "\\xNN" at runtime, which silently
// mishandled any sequence that was not a hex pair (for example the CR/LF inside
// the PNG signature), so those matches were never found.
const std::vector<overlay_magic_t>& overlay_magics() {
  static const std::vector<overlay_magic_t> magics = {
    {"PE",      "Windows PE executable",   "MZ",            2,  0.99},
    {"ELF",     "ELF executable",          "\x7f" "ELF",   4,  0.99},
    {"ZIP",     "ZIP/JAR/APK archive",     "PK\x03\x04",   4,  0.99},
    {"RAR",     "RAR archive",             "Rar!",         4,  0.98},
    {"7Z",      "7-Zip archive",           "7z\xbc\xaf\x27\x1c", 6, 0.99},
    {"GZIP",    "Gzip stream",             "\x1f\x8b",     2,  0.95},
    {"BZIP2",   "Bzip2 stream",            "BZh",          3,  0.95},
    {"XZ",      "XZ stream",               "\xfd" "7zXZ",  6,  0.97},
    {"PDF",     "PDF document",            "%PDF-",        5,  0.99},
    {"PNG",     "PNG image",               "\x89" "PNG\r\n\x1a\n", 8, 0.99},
    {"JPEG",    "JPEG image",              "\xff\xd8\xff", 3,  0.98},
    {"GIF",     "GIF image",               "GIF8",         4,  0.98},
    {"BMP",     "BMP image",               "BM",           2,  0.80},
    {"CAB",     "Microsoft cabinet",       "MSCF",         4,  0.98},
    {"LNK",     "Windows shortcut",        "LNK" "\x00",   4,  0.90},
    {"SQLITE",  "SQLite database",         "SQLite format 3", 16, 0.99},
    {"DEX",     "Android DEX",             "dex\n",        4,  0.97},
    {"CLASS",   "Java class file",         "\xca\xfe\xba\xbe", 4, 0.99},
  };
  return magics;
}


// ---------------------------------------------------------------------------
// PE overlay
// ---------------------------------------------------------------------------

namespace {

// Byte view of a fixed-length magic literal. The table stores explicit lengths
// because several magics contain NUL or non-printable bytes.
std::vector<std::uint8_t> magic_bytes(const overlay_magic_t& magic) {
  return std::vector<std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(magic.bytes),
      reinterpret_cast<const std::uint8_t*>(magic.bytes) + magic.length);
}

}  // namespace

void scan_pe_overlay(pe_overlay_t& result, const std::string& path,
                     std::uint64_t start, std::uint64_t size) {
  // Bound the retained copy: a hostile sample can append a very large blob and
  // we still want entropy, hashing and signature scanning to work on it.
  constexpr std::size_t kMaxRetained = 64u * 1024u * 1024u;

  std::error_code ec;
  const auto file_size = std::filesystem::file_size(path, ec);
  if (ec) return;
  if (size == 0 || start >= file_size) return;
  if (size > file_size - start) size = file_size - start;

  result.present = true;
  result.offset = start;
  result.size = size;

  const std::size_t retained = static_cast<std::size_t>(
      std::min<std::uint64_t>(size, kMaxRetained));
  result.truncated = retained < size;

  std::vector<std::uint8_t> buffer(retained);
  std::ifstream input(path, std::ios::binary);
  if (!input) { result.present = false; return; }
  input.seekg(static_cast<std::streamoff>(start));
  input.read(reinterpret_cast<char*>(buffer.data()),
             static_cast<std::streamsize>(retained));
  buffer.resize(static_cast<std::size_t>(input.gcount()));
  if (buffer.empty()) { result.present = false; return; }

  // Magic preview (hex + printable ASCII) for the first bytes of the overlay.
  {
    const std::size_t preview = std::min<std::size_t>(buffer.size(), 16);
    std::ostringstream hex;
    std::ostringstream ascii;
    for (std::size_t i = 0; i < preview; ++i) {
      static const char* digits = "0123456789ABCDEF";
      hex << digits[(buffer[i] >> 4) & 0x0F] << digits[buffer[i] & 0x0F]
          << (i + 1 == preview ? "" : " ");
      ascii << (std::isprint(buffer[i]) ? static_cast<char>(buffer[i]) : '.');
    }
    result.magic_hex = hex.str();
    result.magic_ascii = ascii.str();
  }

  file_hash_t hash{};
  if (hasher::hash_bytes(hash, buffer.data(), buffer.size())) {
    result.sha256 = hash.hash;
  }
  result.entropy = calculate_entropy(buffer.data(), buffer.size());
  result.chi2 = calculate_chi2(buffer.data(), buffer.size());

  // Scan for every known format so a single overlay can be reported as holding
  // several concatenated files (e.g. a PE followed by a ZIP and a certificate).
  const std::size_t total = buffer.size();
  for (const overlay_magic_t& magic : overlay_magics()) {
    const std::vector<std::uint8_t> needle = magic_bytes(magic);
    if (needle.empty() || needle.size() > total) continue;
    std::size_t position = 0;
    while (position + needle.size() <= total) {
      const auto found_it =
          std::search(buffer.begin() + static_cast<std::ptrdiff_t>(position),
                      buffer.end(), needle.begin(), needle.end());
      if (found_it == buffer.end()) break;
      const auto found = static_cast<std::size_t>(found_it - buffer.begin());
      pe_overlay_signature_t hit{};
      hit.format = magic.name;
      hit.description = magic.description;
      hit.offset = start + found;
      hit.relative_offset = found;
      hit.size = total - found;
      hit.confidence = magic.confidence;
      result.signatures.push_back(std::move(hit));
      position = found + needle.size();
    }
  }

  std::sort(result.signatures.begin(), result.signatures.end(),
            [](const pe_overlay_signature_t& a, const pe_overlay_signature_t& b) {
              if (a.offset != b.offset) return a.offset < b.offset;
              return a.format < b.format;
            });

  result.data = std::move(buffer);
}

void scan_section_strings(strings_result_t& result, const std::string& section_name,
                          std::uint64_t base_offset, const std::uint8_t* data,
                          std::size_t length, std::size_t min_length,
                          std::size_t max_strings) {
  std::size_t i = 0;
  while (i < length) {
    if (!is_string_char(data[i])) { ++i; continue; }
    std::size_t j = i;
    while (j < length && is_string_char(data[j])) ++j;
    if (j - i >= min_length) {
      if (result.strings.size() >= max_strings) { result.truncated = true; return; }
      result.strings.push_back({std::string(reinterpret_cast<const char*>(data + i), j - i),
                                base_offset + i, section_name, "ascii"});
      ++result.ascii_count;
    }
    i = j;
  }

  i = 0;
  while (i + 1 < length) {
    if (!(is_string_char(data[i]) && data[i + 1] == 0x00)) { ++i; continue; }
    std::string text;
    std::size_t j = i;
    while (j + 1 < length && is_string_char(data[j]) && data[j + 1] == 0x00) {
      text.push_back(static_cast<char>(data[j]));
      j += 2;
    }
    if ((j - i) / 2 >= min_length) {
      if (result.strings.size() >= max_strings) { result.truncated = true; return; }
      result.strings.push_back({std::move(text), base_offset + i, section_name, "utf16le"});
      ++result.utf16_count;
    }
    i = j;
  }
}

bool strings_impl(strings_result_t& result, LIEF::Binary& binary, std::size_t min_length,
                  std::size_t max_strings, const std::string& path) {
  if (min_length == 0) min_length = 1;

  bool found_readable = false;
  for (auto& section : binary.sections()) {
    if (!is_readable_section(&section)) continue;
    const LIEF::span<const std::uint8_t> content = section.content();
    if (content.empty()) continue;
    found_readable = true;
    if (result.truncated) break;
    scan_section_strings(result, section.name(), section.offset(), content.data(),
                         content.size(), min_length, max_strings);
  }

  if (!found_readable) {
    if (auto* elf = dynamic_cast<LIEF::ELF::Binary*>(&binary)) {
      std::size_t index = 0;
      for (const LIEF::ELF::Segment& segment : elf->segments()) {
        const std::size_t current = index++;
        if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD) continue;
        const LIEF::span<const std::uint8_t> content = segment.content();
        if (content.empty() || result.truncated) continue;
        found_readable = true;
        scan_section_strings(result, "LOAD#" + std::to_string(current), segment.file_offset(),
                             content.data(), content.size(), min_length, max_strings);
      }
    }
  }

  if (!found_readable) {
    add_error(result.errors, extractor_error::no_strings,
              "No readable sections or segments found for string extraction: " + path);
    return false;
  }
  if (result.strings.empty()) {
    add_error(result.errors, extractor_error::no_strings,
              "No printable strings found above the minimum length");
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Packer
// ---------------------------------------------------------------------------

bool packer_impl(packer_detection_t& result, LIEF::Binary& binary) {
  auto* pe = dynamic_cast<LIEF::PE::Binary*>(&binary);
  auto* elf = dynamic_cast<LIEF::ELF::Binary*>(&binary);

  auto add = [&result](int points, std::string reason) {
    result.score += points;
    result.reasons.push_back(std::move(reason));
  };

  double weighted_entropy = 0.0;
  std::uint64_t total_bytes = 0;
  std::size_t section_count = 0;

  for (auto& section : binary.sections()) {
    ++section_count;
    const std::string name = section.name();
    const LIEF::span<const std::uint8_t> content = section.content();
    const double entropy = calculate_entropy(content.data(), content.size());
    weighted_entropy += entropy * static_cast<double>(content.size());
    total_bytes += content.size();

    const perms_t perms = perms_of(&section);

    if (perms.executable && perms.writable) {
      add(2, "RWX section '" + name + "' (classic unpacking stub)");
    }
    if (const packer_name_t* known = find_packer_name(name)) {
      add(4, "Section '" + name + "' matches a known packer name");
      if (known->family != nullptr && result.suspected_packer.empty()) {
        result.suspected_packer = known->family;
      }
    }
    if (perms.executable && content.size() >= 512 && entropy > 7.2) {
      add(3, "Executable section '" + name + "' has high entropy");
    }
    if (const auto* pe_section = dynamic_cast<const LIEF::PE::Section*>(&section)) {
      if (perms.executable && pe_section->sizeof_raw_data() == 0 &&
          pe_section->virtual_size() >= 0x1000) {
        add(3, "Executable section '" + name + "' has no raw data");
      }
    }
  }

  result.overall_entropy =
      total_bytes > 0 ? weighted_entropy / static_cast<double>(total_bytes) : 0.0;
  if (section_count >= 2 && result.overall_entropy > 7.2) {
    add(2, "Whole-image entropy is very high");
  }

  if (pe != nullptr) {
    const std::uint64_t entry_rva = pe->optional_header().addressof_entrypoint();
    std::size_t index = 0;
    std::size_t last_index = 0;
    std::size_t found_index = 0;
    bool found = false;
    std::string found_name;
    for (const LIEF::PE::Section& section : pe->sections()) {
      const std::uint64_t start = section.virtual_address();
      const std::uint64_t extent =
          std::max<std::uint64_t>(section.virtual_size(), section.sizeof_raw_data());
      if (!found && entry_rva >= start && entry_rva < start + extent) {
        found = true;
        found_index = index;
        found_name = section.name();
      }
      last_index = index++;
    }
    if (index > 0 && entry_rva != 0 && !found) {
      add(2, "Entry point lies outside every section");
    } else if (found && index > 1 && found_index == last_index) {
      add(1, "Entry point is in the last section '" + found_name + "'");
    }

    std::size_t dll_count = 0;
    std::size_t function_count = 0;
    for (const LIEF::PE::Import& import : pe->imports()) {
      ++dll_count;
      function_count += import.entries().size();
    }
    if (dll_count == 0) {
      add(1, "PE imports table is empty");
    } else if (function_count <= 6 && total_bytes >= 32 * 1024) {
      add(1, "Very small import table");
    }
  }

  if (elf != nullptr && section_count == 0) {
    add(1, "ELF has no section headers");

    double segment_weighted = 0.0;
    std::uint64_t segment_bytes = 0;
    bool upx_marker_reported = false;
    for (const LIEF::ELF::Segment& segment : elf->segments()) {
      if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD) continue;
      const LIEF::span<const std::uint8_t> content = segment.content();
      if (content.empty()) continue;
      segment_weighted += calculate_entropy(content.data(), content.size()) *
                          static_cast<double>(content.size());
      segment_bytes += content.size();

      if (segment.file_offset() == 0 && !upx_marker_reported) {
        const std::string_view head(reinterpret_cast<const char*>(content.data()),
                                    std::min<std::size_t>(content.size(), 1024));
        if (head.find("UPX!") != std::string_view::npos) {
          upx_marker_reported = true;
          add(4, "UPX header marker found in the first LOAD segment");
          if (result.suspected_packer.empty()) result.suspected_packer = "UPX";
        }
      }
    }
    result.overall_entropy =
        segment_bytes > 0 ? segment_weighted / static_cast<double>(segment_bytes) : 0.0;
    if (result.overall_entropy > 7.2) {
      add(3, "Loadable segments have very high entropy");
    }
  }

  result.packed = result.score >= 3;
  result.confidence = result.score >= 6 ? "high" : (result.score >= 3 ? "medium" : "low");
  return true;
}

// ---------------------------------------------------------------------------
// Opcodes
// ---------------------------------------------------------------------------

bool opcodes_impl(opcode_stats_t& result, LIEF::Binary& binary) {
  const LIEF::Header header = binary.header();
  cs_arch arch{};
  cs_mode mode{};
  if (!resolve_capstone_arch(header, arch, mode, result.architecture)) {
    add_error(result.errors, extractor_error::unsupported_format,
              "Capstone does not support architecture '" + result.architecture + "'");
    return false;
  }

  csh handle = 0;
  const cs_err open_error = cs_open(arch, mode, &handle);
  if (open_error != CS_ERR_OK) {
    add_error(result.errors, extractor_error::capstone_failed,
              std::string("cs_open failed: ") + cs_strerror(open_error));
    return false;
  }

  const bool is_x86 = arch == CS_ARCH_X86;
  cs_option(handle, CS_OPT_DETAIL, is_x86 ? CS_OPT_ON : CS_OPT_OFF);
  const bool big_endian = (mode & CS_MODE_BIG_ENDIAN) != 0;

  cs_insn* insn = cs_malloc(handle);
  if (insn == nullptr) {
    cs_close(&handle);
    add_error(result.errors, extractor_error::capstone_failed, "cs_malloc failed");
    return false;
  }

  std::array<std::uint64_t, 256> raw_counts{};
  std::unordered_map<unsigned, std::uint64_t> id_counts;
  std::uint64_t disassembled = 0;
  bool found_code = false;

  auto sweep = [&](const LIEF::span<const std::uint8_t>& content, std::uint64_t start_address) {
    const std::uint8_t* code = content.data();
    std::size_t remaining = content.size();
    std::uint64_t address = start_address;
    result.code_bytes += remaining;

    while (remaining > 0) {
      if (cs_disasm_iter(handle, &code, &remaining, &address, insn)) {
        std::uint8_t opcode = insn->bytes[0];
        if (is_x86 && insn->detail != nullptr) {
          opcode = insn->detail->x86.opcode[0];
        } else if (!big_endian && insn->size == 4) {
          opcode = insn->bytes[3];
        }
        raw_counts[opcode]++;
        id_counts[insn->id]++;
        result.decoded_bytes += insn->size;
        ++disassembled;
      } else {
        ++code;
        --remaining;
        ++address;
        ++result.invalid_bytes;
      }
    }
  };

  for (auto& section : binary.sections()) {
    if (!is_code_section(&section)) continue;
    found_code = true;
    sweep(section.content(), section.virtual_address());
  }
  if (!found_code) {
    if (auto* elf = dynamic_cast<LIEF::ELF::Binary*>(&binary)) {
      for (const LIEF::ELF::Segment& segment : elf->segments()) {
        if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD ||
            !segment.has(LIEF::ELF::Segment::FLAGS::X)) {
          continue;
        }
        found_code = true;
        sweep(segment.content(), segment.virtual_address());
      }
    }
  }

  if (!found_code) {
    cs_free(insn, 1);
    cs_close(&handle);
    add_error(result.errors, extractor_error::no_code_section,
              "No executable section was found to disassemble");
    return false;
  }

  std::vector<std::pair<unsigned, std::uint64_t>> ranked(id_counts.begin(), id_counts.end());
  std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
    return a.second != b.second ? a.second > b.second : a.first < b.first;
  });
  for (std::size_t i = 0; i < ranked.size() && i < 16; ++i) {
    const char* name = cs_insn_name(handle, ranked[i].first);
    mnemonic_count_t entry;
    entry.mnemonic = name != nullptr ? name : ("id_" + std::to_string(ranked[i].first));
    entry.count = ranked[i].second;
    entry.frequency = static_cast<double>(entry.count) / static_cast<double>(disassembled);
    result.top_mnemonics.push_back(std::move(entry));
  }

  cs_free(insn, 1);
  cs_close(&handle);

  for (std::size_t i = 0; i < 256; ++i) {
    result.counts[i] = static_cast<std::uint32_t>(raw_counts[i]);
    result.frequencies[i] = disassembled > 0
        ? static_cast<double>(raw_counts[i]) / static_cast<double>(disassembled)
        : 0.0;
  }
  result.total_instructions = disassembled;
  result.coverage = result.code_bytes > 0
      ? static_cast<double>(result.decoded_bytes) / static_cast<double>(result.code_bytes)
      : 0.0;
  return true;
}

// ---------------------------------------------------------------------------
// Debug symbols
// ---------------------------------------------------------------------------

bool debug_impl(debug_symbols_t& result, LIEF::Binary& binary, std::size_t max_symbols) {
  for (const LIEF::Section& section : binary.sections()) {
    const std::string name = section.name();
    if (is_debug_section_name(name)) {
      result.has_debug_sections = true;
      result.debug_sections.push_back(name);
    }
  }

  const bool demangle_supported = LIEF::is_extended();

  auto keep = [&result, max_symbols](debug_symbol_t&& entry) {
    ++result.symbol_count;
    if (result.symbols.size() < max_symbols) {
      result.symbols.push_back(std::move(entry));
    } else {
      result.truncated = true;
    }
  };

  if (auto* elf = dynamic_cast<LIEF::ELF::Binary*>(&binary)) {
    result.format = "ELF";
    std::unordered_set<std::string> seen;

    const auto record_elf_symbol = [&](const LIEF::ELF::Symbol& symbol, const char* source) {
      if (!seen.insert(symbol.name() + "@" + std::to_string(symbol.value())).second) return;
      debug_symbol_t entry{};
      entry.name = symbol.name();
      entry.demangled_name = demangle_supported ? symbol.demangled_name() : std::string();
      entry.address = symbol.value();
      entry.size = symbol.size();
      entry.type = LIEF::ELF::to_string(symbol.type());
      entry.binding = LIEF::ELF::to_string(symbol.binding());
      entry.visibility = LIEF::ELF::to_string(symbol.visibility());
      if (const LIEF::ELF::SymbolVersion* version = symbol.symbol_version()) {
        if (version->has_auxiliary_version() &&
            version->symbol_version_auxiliary() != nullptr) {
          entry.version = version->symbol_version_auxiliary()->name();
        } else {
          entry.version = std::to_string(version->value());
        }
      }
      entry.imported = symbol.is_imported();
      entry.exported = symbol.is_exported();
      entry.undefined = symbol.shndx() == 0;
      entry.source = source;
      keep(std::move(entry));
    };

    for (const LIEF::ELF::Symbol& symbol : elf->symtab_symbols())
      record_elf_symbol(symbol, "symtab");
    for (const LIEF::ELF::Symbol& symbol : elf->dynamic_symbols())
      record_elf_symbol(symbol, "dynsym");

    result.stripped = elf->symtab_symbols().empty();
  } else if (auto* pe = dynamic_cast<LIEF::PE::Binary*>(&binary)) {
    result.format = "PE";
    for (const LIEF::COFF::Symbol& symbol : pe->symbols()) {
      debug_symbol_t entry{};
      entry.name = symbol.name();
      entry.demangled_name = demangle_supported ? symbol.demangled_name() : std::string();
      entry.address = symbol.value();
      entry.type = LIEF::COFF::to_string(symbol.storage_class());
      entry.binding = symbol.is_external() ? "EXTERNAL" : entry.type;
      entry.imported = symbol.is_undefined();
      entry.exported = symbol.is_external() && !symbol.is_undefined();
      entry.undefined = symbol.is_undefined();
      entry.source = "coff";
      keep(std::move(entry));
    }

    if (const LIEF::PE::CodeViewPDB* pdb = pe->codeview_pdb()) {
      result.pdb_filename = pdb->filename();
      result.pdb_guid = pdb->guid();
      result.pdb_age = pdb->age();
    }
    for (const LIEF::PE::Debug& debug : pe->debug()) {
      if (debug.timestamp() != 0) result.pdb_timestamp = debug.timestamp();
    }

    result.has_debug_sections = result.has_debug_sections || pe->has_debug();
    result.stripped = pe->symbols().empty() && !pe->has_debug();
  } else if (auto* macho = dynamic_cast<LIEF::MachO::Binary*>(&binary)) {
    result.format = "MachO";
    for (const LIEF::MachO::Symbol& symbol : macho->symbols()) {
      debug_symbol_t entry{};
      entry.name = symbol.name();
      entry.demangled_name = demangle_supported ? symbol.demangled_name() : std::string();
      entry.address = symbol.value();
      entry.type = LIEF::MachO::to_string(symbol.type());
      entry.binding = LIEF::MachO::to_string(symbol.category());
      entry.imported = symbol.is_external();
      entry.exported = symbol.has_export_info();
      entry.undefined = symbol.is_external();
      entry.source = "macho";
      keep(std::move(entry));
    }
    result.stripped = macho->symbols().empty();
  } else {
    result.format = "Unknown";
  }

  result.has_debug_symbols = result.symbol_count > 0;

  if (!result.has_debug_symbols && !result.has_debug_sections &&
      result.pdb_filename.empty()) {
    add_error(result.errors, extractor_error::no_debug_symbols,
              "No debug symbol table, debug section or PDB reference found");
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

bool signature_impl(signature_info_t& result, LIEF::Binary& binary) {
  if (auto* pe = dynamic_cast<LIEF::PE::Binary*>(&binary)) {
    result.format = "PE";

    const auto& signatures = pe->signatures();
    if (signatures.empty()) {
      add_error(result.errors, extractor_error::no_signature,
                "PE file is not Authenticode-signed");
      return false;
    }

    result.has_signature  = true;
    result.is_signed      = true;
    result.num_signatures = signatures.size();

    for (const LIEF::PE::Signature& sig : signatures) {
      std::string note = "signature present";

      if (result.digest_algorithm.empty()) {
        result.digest_algorithm = LIEF::PE::to_string(sig.digest_algorithm());
      }

      const LIEF::PE::x509* leaf = nullptr;
      for (const LIEF::PE::x509& cert : sig.certificates()) {
        bool issues_another = false;
        for (const LIEF::PE::x509& other : sig.certificates()) {
          if (&other != &cert && other.issuer() == cert.subject() &&
              other.subject() != cert.subject()) {
            issues_another = true;
            break;
          }
        }
        if (!issues_another) { leaf = &cert; break; }
      }
      if (leaf != nullptr) {
        if (result.signer.empty()) result.signer = leaf->subject();
        if (result.issuer.empty()) result.issuer = leaf->issuer();
      }

      result.details.push_back(std::move(note));
    }

    try {
      const auto verdict = pe->verify_signature();
      result.is_valid = verdict == LIEF::PE::Signature::VERIFICATION_FLAGS::OK;
      result.verification = result.is_valid
          ? std::string("OK")
          : LIEF::PE::Signature::flag_to_string(verdict);
    } catch (const std::exception& e) {
      result.is_valid = false;
      result.verification = std::string("verification failed: ") + e.what();
    }
    return true;
  }

  if (auto* macho = dynamic_cast<LIEF::MachO::Binary*>(&binary)) {
    result.format = "MachO";

    if (!macho->has_code_signature()) {
      add_error(result.errors, extractor_error::no_signature,
                "Mach-O has no LC_CODE_SIGNATURE load command");
      return false;
    }

    result.has_signature  = true;
    result.is_signed      = true;
    result.num_signatures = 1;
    result.details.push_back("LC_CODE_SIGNATURE present");
    result.verification = "not verified (presence only)";
    return true;
  }

  if (auto* elf = dynamic_cast<LIEF::ELF::Binary*>(&binary)) {
    result.format = "ELF";

    static constexpr const char* SIG_SECTIONS[] = {
        ".signature", ".sig", ".note.sig", ".gpg", ".gpgsig",
        ".gnu.signature", ".module_sig",
    };

    bool found = false;
    for (const LIEF::Section& section : elf->sections()) {
      const std::string name = section.name();
      for (const char* candidate : SIG_SECTIONS) {
        if (name == candidate) {
          found = true;
          result.details.push_back("Found signature section: " + name);
          break;
        }
      }
    }

    if (!found) {
      add_error(result.errors, extractor_error::no_signature,
                "ELF has no embedded signature section");
      return false;
    }

    result.has_signature  = true;
    result.is_signed      = true;
    result.num_signatures = result.details.size();
    result.verification = "not verified (presence only)";
    return true;
  }

  result.format = "Unknown";
  add_error(result.errors, extractor_error::unsupported_format,
            "Signature check not supported for this format");
  return false;
}

// ---------------------------------------------------------------------------
// Byte histogram (whole file, raw bytes, no LIEF needed)
// ---------------------------------------------------------------------------

void finalize_histogram(byte_histogram_t& result) {
  const double total = static_cast<double>(result.total_bytes);
  if (result.total_bytes == 0) {
    result.entropy = 0.0;
    result.chi2 = 0.0;
    result.mean = 0.0;
    result.stddev = 0.0;
    return;
  }

  double entropy = 0.0;
  double sum = 0.0;
  double sum_sq = 0.0;
  std::uint64_t max_count = 0;
  std::uint64_t min_count = result.total_bytes;
  const double expected = total / 256.0;
  double chi2 = 0.0;

  for (std::size_t i = 0; i < 256; ++i) {
    const std::uint64_t count = result.counts[i];
    result.frequencies[i] = static_cast<double>(count) / total;
    // EMBER ByteHistogram: normalized counts (process_raw_features).
    result.ember_histogram[i] = result.frequencies[i];
    const double diff = static_cast<double>(count) - expected;
    chi2 += (diff * diff) / expected;
    if (count == 0) continue;
    ++result.nonzero_bins;
    const double probability = static_cast<double>(count) / total;
    entropy -= probability * std::log2(probability);
    if (count > max_count) {
      max_count = count;
      result.most_common_byte = static_cast<std::uint8_t>(i);
    }
    if (count < min_count) {
      min_count = count;
      result.least_common_byte = static_cast<std::uint8_t>(i);
    }
    sum += static_cast<double>(i) * static_cast<double>(count);
    sum_sq += static_cast<double>(i) * static_cast<double>(i) *
              static_cast<double>(count);
  }

  result.entropy = entropy;
  result.chi2 = chi2;
  result.mean = sum / total;
  const double variance = sum_sq / total - result.mean * result.mean;
  result.stddev = variance > 0.0 ? std::sqrt(variance) : 0.0;
  result.zero_bytes = result.counts[0];
}

bool histogram_impl(byte_histogram_t& result, const analyzer::file_info_t& info) {
  result = {};
  if (!check_file_ok(info, result.errors)) return false;

  std::ifstream input(info.filepath, std::ios::binary);
  if (!input) {
    add_error(result.errors, extractor_error::read_failed,
              "Could not open file for byte histogram: " + info.filepath);
    return false;
  }

  // Stream in chunks so very large samples never need a full copy in RAM.
  // The byte/entropy pass needs 2048-byte windows at 1024 stride; keep a
  // rolling window buffer alongside the chunk stream. Feed the entropy pass
  // byte-by-byte (cheap shift of a 2048-slot ring); accumulate only window
  // starts (every 1024 bytes) plus the tail remainder, exactly like processing
  // the whole file at once.
  std::array<char, 65536> buffer{};
  std::array<std::uint8_t, 2048> ring{};
  std::size_t ring_fill = 0;   // bytes seen so far in current window cycle
  std::uint64_t stream_pos = 0;
  std::uint64_t joint[256] = {};
  auto accumulate_ring = [&]() {
    std::uint64_t coarse[16] = {};
    for (std::size_t k = 0; k < 2048; ++k) coarse[ring[k] >> 4]++;
    double h = 0.0;
    for (int b = 0; b < 16; ++b) {
      if (coarse[b] == 0) continue;
      const double p = static_cast<double>(coarse[b]) / 2048.0;
      h -= p * std::log2(p);
    }
    h *= 2.0;
    int hbin = static_cast<int>(h * 2.0);
    if (hbin < 0) hbin = 0;
    if (hbin > 15) hbin = 15;
    for (int b = 0; b < 16; ++b) {
      if (coarse[b] == 0) continue;
      joint[static_cast<std::size_t>(hbin) * 16 +
            static_cast<std::size_t>(b)] += coarse[b];
    }
  };
  bool any = false;
  while (input) {
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize got = input.gcount();
    if (got <= 0) break;
    any = true;
    for (std::streamsize i = 0; i < got; ++i) {
      const std::uint8_t b =
          static_cast<std::uint8_t>(buffer[static_cast<std::size_t>(i)]);
      result.counts[b]++;
      ++result.total_bytes;
      // Ring holds the last up-to-2048 bytes ending at stream_pos.
      if (ring_fill < 2048) {
        ring[ring_fill++] = b;
      } else {
        std::memmove(ring.data(), ring.data() + 1, 2047);
        ring[2047] = b;
      }
      ++stream_pos;
      // Window starts at offsets 0, 1024, 2048, ... once 2048 bytes seen.
      if (ring_fill == 2048 && (stream_pos - 2048) % 1024 == 0)
        accumulate_ring();
    }
  }

  if (!any || result.total_bytes == 0) {
    add_error(result.errors, extractor_error::empty_file,
              "File has no bytes for byte histogram: " + info.filepath);
    return false;
  }

  // Tail: files shorter than one window. thrember divides the coarse histogram
  // by self.window (2048) unconditionally -- including for a short file, where
  // the block is the whole file -- so the denominator stays 2048 here even
  // though the block holds fewer bytes. Using ring_fill instead silently lands
  // the result in a different entropy bin.
  if (result.total_bytes < 2048) {
    std::uint64_t coarse[16] = {};
    for (std::size_t k = 0; k < ring_fill; ++k) coarse[ring[k] >> 4]++;
    double h = 0.0;
    for (int b = 0; b < 16; ++b) {
      if (coarse[b] == 0) continue;
      const double p = static_cast<double>(coarse[b]) / 2048.0;
      h -= p * std::log2(p);
    }
    h *= 2.0;
    int hbin = static_cast<int>(h * 2.0);
    if (hbin < 0) hbin = 0;
    if (hbin > 15) hbin = 15;
    for (int b = 0; b < 16; ++b) {
      if (coarse[b] == 0) continue;
      joint[static_cast<std::size_t>(hbin) * 16 +
            static_cast<std::size_t>(b)] += coarse[b];
    }
  }

  std::uint64_t grand = 0;
  for (int i = 0; i < 256; ++i) grand += joint[i];
  if (grand != 0) {
    const double g = static_cast<double>(grand);
    for (int i = 0; i < 256; ++i)
      result.ember_byteentropy[i] = static_cast<double>(joint[i]) / g;
  }

  finalize_histogram(result);
  return true;
}

// ---------------------------------------------------------------------------
// Pipeline helpers
// ---------------------------------------------------------------------------

template <class Fn>
void run_stage(extraction_result_t& result, const char* name, Fn&& fn) {
  const auto started = clock_type::now();
  fn();
  const double elapsed = seconds_since(started);
  result.timings.push_back({name, elapsed});
}

struct capa_job {
  std::future<capa_result_t> future;
  bool active = false;
};

capa_job start_capa(const analyzer::file_info_t& info, const analysis_options_t& options) {
  capa_job job;
  if (!options.run_capa) return job;
  error_type_t precheck;
  if (!check_file_ok(info, precheck)) return job;
  job.active = true;
  job.future = std::async(std::launch::async, [&info, &options]() {
    capa_result_t capa_result;
    extract_capa(capa_result, info, options.capa);
    return capa_result;
  });
  return job;
}

bool run_pipeline(extraction_result_t& result, const analyzer::file_info_t& info,
                  const analysis_options_t& options, capa_job& job,
                  clock_type::time_point pipeline_start) {
  error_type_t input;
  std::unique_ptr<LIEF::Binary> binary;
  if (check_file_ok(info, input)) {
    binary = load_binary_safe(info.filepath, input);
  }

  if (!binary) {
    result.input_errors = input;
  } else {
    LIEF::Binary& bin = *binary;
    const bool is_pe    = dynamic_cast<LIEF::PE::Binary*>(&bin) != nullptr;
    const bool is_elf   = dynamic_cast<LIEF::ELF::Binary*>(&bin) != nullptr;
    const bool is_macho = dynamic_cast<LIEF::MachO::Binary*>(&bin) != nullptr;

    run_stage(result, "guards", [&] { guard_impl(result.guards, bin); });
    if (is_elf) run_stage(result, "elf", [&] { elf_impl(result.elf, bin, info.filepath); });
    if (is_pe)  run_stage(result, "pe",  [&] { pe_impl(result.pe, bin, info.filepath); });
    run_stage(result, "sections", [&] { sections_impl(result.sections, bin); });
    run_stage(result, "strings", [&] {
      strings_impl(result.strings, bin, options.min_string_length, options.max_strings,
                   info.filepath);
    });
    // The histogram reads raw bytes only - no LIEF object needed - so the
    // stage goes through the public entry point, like the xxd/cminer stages.
    run_stage(result, "histogram", [&] { extract_byte_histogram(result.histogram, info); });
    run_stage(result, "packer", [&] { packer_impl(result.packer, bin); });
    run_stage(result, "opcodes", [&] { opcodes_impl(result.opcodes, bin); });
    run_stage(result, "debug", [&] { debug_impl(result.debug_symbols, bin, options.max_symbols); });
    run_stage(result, "signature", [&] { signature_impl(result.signature, bin); });
    if (is_elf || is_macho) {
      run_stage(result, "got", [&] {
        got_impl(result.got, bin, info.filepath, options.max_got_entries);
      });
    }
  }
  run_stage(result, "hexdump", [&] { extract_hexdump(result.hexdump, info); });
  run_stage(result, "cminer", [&] {
    extract_cminer(result.cminer, info, options.cminer_min_cave_size);
  });
  // YARA used to be scanned here. It is cheap to re-enable: without it the
  // extraction JSON always serialises an empty `yara` object (attempted=false),
  // so the dashboard YARA card and the exported report show nothing at all.
  run_stage(result, "yara", [&] {
    yara_scanner::scan_pe(result.yara, info);
  });
  if (job.active) {
    result.capa = job.future.get();
    result.timings.push_back({"capa (wait)", 0.0});
  }

  const error_type_t* stage_errors[] = {
      &result.input_errors,     &result.guards.errors,      &result.elf.errors,
      &result.pe.errors,        &result.pe.iat.errors,      &result.elf.got.errors,
      &result.got.errors,       &result.sections.errors,    &result.strings.errors,
      &result.histogram.errors, &result.packer.errors,     &result.opcodes.errors,
      &result.debug_symbols.errors,
      &result.signature.errors, &result.capa.errors, &result.hexdump.errors,
      &result.cminer.errors};
  for (const error_type_t* errors : stage_errors) {
    if (errors->flags == extractor_error::none) continue;
    result.errors.flags |= errors->flags;
    if (!result.errors.details.empty()) result.errors.details += '\n';
    result.errors.details += errors->details;
    for (const std::string& message : errors->messages) {
      result.errors.messages.push_back(message);
    }
  }
  result.total_seconds = seconds_since(pipeline_start);

  std::uint32_t soft = static_cast<std::uint32_t>(soft_errors);
  if (options.capa_required) {
    soft &= ~static_cast<std::uint32_t>(extractor_error::capa_not_found |
                                        extractor_error::capa_failed |
                                        extractor_error::capa_timeout);
  }
  return (static_cast<std::uint32_t>(result.errors.flags) & ~soft) == 0;
}

}  // anonymous namespace

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

void add_error(error_type_t& errors, extractor_error error,
               const std::string& detail) {
  errors.flags |= error;
  errors.messages.push_back(std::string("[") + error_name(error) + "] " + detail);
  if (!errors.details.empty()) errors.details += '\n';
  errors.details += detail;
}

bool has_errors(const error_type_t& errors) {
  return errors.flags != extractor_error::none;
}

std::vector<std::string> get_error_messages(const error_type_t& errors) {
  return errors.messages;
}

// ---------------------------------------------------------------------------
// Entropy / chi²
// ---------------------------------------------------------------------------

double calculate_entropy(const std::uint8_t* bytes, std::size_t size) {
  if (bytes == nullptr || size == 0) return 0.0;
  std::array<std::uint64_t, 256> counts{};
  for (std::size_t i = 0; i < size; ++i) counts[bytes[i]]++;
  double entropy = 0.0;
  const double total = static_cast<double>(size);
  for (std::size_t i = 0; i < 256; ++i) {
    if (counts[i] == 0) continue;
    const double probability = static_cast<double>(counts[i]) / total;
    entropy -= probability * std::log2(probability);
  }
  return entropy;
}

double calculate_chi2(const std::uint8_t* bytes, std::size_t size) {
  if (bytes == nullptr || size == 0) return 0.0;
  std::array<std::uint64_t, 256> observed{};
  for (std::size_t i = 0; i < size; ++i) observed[bytes[i]]++;
  const double expected = static_cast<double>(size) / 256.0;
  double chi2 = 0.0;
  for (std::size_t i = 0; i < 256; ++i) {
    const double diff = static_cast<double>(observed[i]) - expected;
    chi2 += (diff * diff) / expected;
  }
  return chi2;
}

// ---------------------------------------------------------------------------
// Public extract_* entry points
// ---------------------------------------------------------------------------

bool extract_guard_info(guard_info_t& result, const analyzer::file_info_t& info) {
  return with_binary(result, info, [&](LIEF::Binary& binary) { return guard_impl(result, binary); });
}

bool extract_elf_sections(elf_sections_t& result, const analyzer::file_info_t& info) {
  return with_binary(result, info, [&](LIEF::Binary& binary) {
    return elf_impl(result, binary, info.filepath);
  });
}

bool extract_pe_sections(pe_sections_t& result, const analyzer::file_info_t& info) {
  return with_binary(result, info, [&](LIEF::Binary& binary) {
    return pe_impl(result, binary, info.filepath);
  });
}

bool extract_iat(iat_result_t& result, const analyzer::file_info_t& info,
                 std::size_t max_entries) {
  return with_binary(result, info, [&](LIEF::Binary& binary) {
    return iat_impl(result, binary, info.filepath, max_entries);
  });
}

bool extract_got(got_result_t& result, const analyzer::file_info_t& info,
                 std::size_t max_entries) {
  return with_binary(result, info, [&](LIEF::Binary& binary) {
    return got_impl(result, binary, info.filepath, max_entries);
  });
}

bool extract_sections(sections_result_t& result, const analyzer::file_info_t& info) {
  return with_binary(result, info, [&](LIEF::Binary& binary) { return sections_impl(result, binary); });
}

bool extract_strings(strings_result_t& result, const analyzer::file_info_t& info,
                     std::size_t min_length, std::size_t max_strings) {
  return with_binary(result, info, [&](LIEF::Binary& binary) {
    return strings_impl(result, binary, min_length, max_strings, info.filepath);
  });
}

bool extract_byte_histogram(byte_histogram_t& result,
                            const analyzer::file_info_t& info) {
  result = {};
  if (!check_file_ok(info, result.errors)) return false;
  return histogram_impl(result, info);
}

bool detect_if_packed(packer_detection_t& result, const analyzer::file_info_t& info) {
  return with_binary(result, info, [&](LIEF::Binary& binary) { return packer_impl(result, binary); });
}

bool generate_opcode_stats(opcode_stats_t& result, const analyzer::file_info_t& info) {
  return with_binary(result, info, [&](LIEF::Binary& binary) { return opcodes_impl(result, binary); });
}

bool extract_debug_symbols(debug_symbols_t& result, const analyzer::file_info_t& info,
                           std::size_t max_symbols) {
  return with_binary(result, info, [&](LIEF::Binary& binary) {
    return debug_impl(result, binary, max_symbols);
  });
}

bool extract_hexdump(hexdump_result_t& result, const analyzer::file_info_t& info,
                     std::size_t max_bytes) {
  result = {};
  result.attempted = true;
  if (!check_file_ok(info, result.errors)) return false;

  const auto started = std::chrono::steady_clock::now();

  std::ifstream input(info.filepath, std::ios::binary);
  if (!input) {
    LOG_ERROR("extractor: extract_hexdump: cannot open '{}'", info.filepath);
    add_error(result.errors, extractor_error::hexdump_read_failed,
              "Could not open file for hexdump: " + info.filepath);
    return false;
  }

  result.total_bytes = info.size;

  // Read exactly the window we want. `truncated` then compares what we got
  // against the size file_analyzer measured, which is a fact about the file
  // rather than an inference from a byte we happened to probe for.
  const std::size_t want = max_bytes;
  result.bytes.resize(want);
  input.read(reinterpret_cast<char*>(result.bytes.data()),
             static_cast<std::streamsize>(want));
  const std::streamsize got = input.gcount();
  if (got < 0) {
    result.bytes.clear();
    LOG_ERROR("extractor: extract_hexdump: read error on '{}'", info.filepath);
    add_error(result.errors, extractor_error::hexdump_read_failed,
              "Read error while dumping " + info.filepath);
    return false;
  }
  result.bytes.resize(static_cast<std::size_t>(got));
  result.available = true;
  result.truncated = static_cast<std::size_t>(got) < info.size;

  LOG_DEBUG("extractor: extract_hexdump: '{}' -> {} of {} byte(s) in {:.4f}s",
            info.filename, result.bytes.size(), info.size,
            std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count());

  result.seconds = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - started).count();
  return true;
}

bool extract_cminer(cminer_result_t& result, const analyzer::file_info_t& info,
                     std::size_t minimum_cave_size) {
  result = {};
  result.minimum_cave_size = std::max<std::size_t>(100, minimum_cave_size);
  if (info.type.executable_type.find("PE") == std::string::npos) {
    result.applicable = false;
    return false;
  }
  result.applicable = true;
  result.attempted = true;
  if (!check_file_ok(info, result.errors)) return false;

  const auto started = clock_type::now();
  result.command = "native in-process cave scan";

  // The scan runs in-process: LIEF supplies the PE section table and the raw
  // bytes are streamed in chunks. The bundled Cminer CLI shelled out through
  // `system()` with unquoted paths, so a sample under "Program Files (x86)"
  // died with `sh: Syntax error: "(" unexpected` before it could scan (and
  // its .bak copy could not have been written under Program Files anyway).
  auto binary = load_binary_safe(info.filepath, result.errors);
  if (!binary) return false;
  auto* pe = dynamic_cast<LIEF::PE::Binary*>(binary.get());
  if (pe == nullptr) {
    add_error(result.errors, extractor_error::unsupported_format,
              "Cave scan expects a PE image: " + info.filepath);
    return false;
  }

  struct cave_section_t {
    std::string   name;
    std::uint64_t raw_offset;
    std::uint64_t raw_size;
    std::uint64_t virtual_address;
  };
  std::vector<cave_section_t> sections;
  sections.reserve(pe->sections().size());
  for (auto& section : pe->sections()) {
    if (section.sizeof_raw_data() == 0) continue;
    cave_section_t item;
    item.name = section.name();
    item.raw_offset = section.offset();
    item.raw_size = section.sizeof_raw_data();
    item.virtual_address = section.virtual_address();
    sections.push_back(std::move(item));
  }
  // Caves are located by file offset; the sorted table is walked in order
  // and stops at the first section that starts after the cave.
  std::sort(sections.begin(), sections.end(),
            [](const cave_section_t& a, const cave_section_t& b) {
              return a.raw_offset < b.raw_offset;
            });
  // Cminer printed objdump's VMA column, i.e. ImageBase + RVA.
  const std::uint64_t image_base = pe->optional_header().imagebase();

  std::ifstream input(info.filepath, std::ios::binary);
  if (!input) {
    add_error(result.errors, extractor_error::read_failed,
              "Could not open the file for the cave scan: " + info.filepath);
    return false;
  }

  const auto emit_cave = [&](std::uint64_t start, std::uint64_t size) {
    // Like Cminer, only runs strictly longer than the threshold count.
    if (size <= result.minimum_cave_size) return;
    cminer_cave_t cave;
    cave.size = size;
    cave.file_offset = start;
    // Caves outside any section keep their file offsets (Cminer's
    // "No Section." case); inside a section the address is virtual.
    cave.section = "No Section.";
    cave.start_address = start;
    cave.end_address = start + size;
    for (const cave_section_t& section : sections) {
      if (start < section.raw_offset) break;
      if (start >= section.raw_offset + section.raw_size) continue;
      cave.section = section.name.empty() ? "(unnamed)" : section.name;
      cave.start_address =
          image_base + section.virtual_address + (start - section.raw_offset);
      cave.end_address = cave.start_address + size;
      break;
    }
    result.total_cave_bytes += cave.size;
    result.largest_cave_bytes = std::max(result.largest_cave_bytes, cave.size);
    result.caves.push_back(cave);
  };

  // Stream in 64 KiB chunks and carry the run across chunk boundaries; a run
  // that reaches EOF is flushed after the loop (Cminer dropped that cave).
  std::array<char, 65536> buffer{};
  std::uint64_t position = 0;
  std::uint64_t run_start = 0;
  std::uint64_t run_length = 0;
  while (input) {
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize got = input.gcount();
    if (got <= 0) break;
    for (std::streamsize i = 0; i < got; ++i) {
      if (buffer[static_cast<std::size_t>(i)] == '\0') {
        if (run_length == 0) run_start = position;
        ++run_length;
      } else if (run_length > 0) {
        emit_cave(run_start, run_length);
        run_length = 0;
      }
      ++position;
    }
  }
  if (run_length > 0) emit_cave(run_start, run_length);

  result.seconds = seconds_since(started);
  result.exit_code = 0;
  result.available = true;
  LOG_DEBUG("extractor: extract_cminer: '{}' -> {} cave(s), {} byte(s) in {:.4f}s",
            info.filename, result.caves.size(), result.total_cave_bytes,
            result.seconds);
  return true;
}

bool extract_signature_info(signature_info_t& result, const analyzer::file_info_t& info) {
  return with_binary(result, info, [&](LIEF::Binary& binary) { return signature_impl(result, binary); });
}

// ---------------------------------------------------------------------------
// capa
// ---------------------------------------------------------------------------

bool extract_capa(capa_result_t& result, const analyzer::file_info_t& info,
                  const capa_options_t& options) {
  result = {};
  if (!check_file_ok(info, result.errors)) return false;

  if (info.type.executable_type.find("Mach") != std::string::npos) {
    add_error(result.errors, extractor_error::unsupported_format,
              "capa does not analyze Mach-O binaries");
    return false;
  }

  result.attempted = true;
  capa::report_t report = capa::analyze_file(info.filepath, options);
  result.seconds = report.seconds;
  result.exit_code = report.exit_code;
  result.from_cache = report.from_cache;
  result.warnings = report.warnings;
  result.stderr_tail = report.stderr_tail;

  if (!report.ok()) {
    extractor_error code = extractor_error::capa_failed;
    switch (report.st) {
      case capa::status::not_found:    code = extractor_error::capa_not_found; break;
      case capa::status::timed_out:    code = extractor_error::capa_timeout; break;
      case capa::status::file_missing: code = extractor_error::invalid_path; break;
      default: break;
    }
    add_error(result.errors, code, report.error);
    if (!report.stderr_tail.empty()) {
      add_error(result.errors, code, "capa stderr: " + report.stderr_tail);
    }
    return false;
  }

  result.version = report.capa_version;
  result.format = report.format;
  result.arch = report.arch;
  result.os = report.os;
  result.backend = report.backend;
  result.rules_matched = report.rules_matched;
  result.library_rules = report.library_rules;
  result.attack_ids = capa::attack_ids(report);
  result.mbc_ids = capa::mbc_ids(report);
  result.categories = capa::capabilities_by_category(report);
  result.capabilities = std::move(report.capabilities);
  return true;
}

// ---------------------------------------------------------------------------
// Whole-file analysis
// ---------------------------------------------------------------------------

bool analyze(extraction_result_t& result, const analyzer::file_info_t& info) {
  return analyze(result, info, analysis_options_t{});
}

bool analyze(extraction_result_t& result, const analyzer::file_info_t& info,
             const analysis_options_t& options) {
  result = {};
  const auto started = clock_type::now();
  capa_job job = start_capa(info, options);
  return run_pipeline(result, info, options, job, started);
}

bool analyze_with_hashes(extraction_result_t& result, analyzer::file_info_t& info) {
  return analyze_with_hashes(result, info, analysis_options_t{});
}

bool analyze_with_hashes(extraction_result_t& result, analyzer::file_info_t& info,
                         const analysis_options_t& options) {
  result = {};
  const auto started = clock_type::now();
  capa_job job = start_capa(info, options);

  run_stage(result, "sha256", [&] {
    if (!hasher::hash_file(result.sha256, info)) {
      add_error(result.errors, extractor_error::hash_failed, "SHA256 hashing failed");
      for (const auto& msg : hasher::get_hash_error_messages(result.sha256)) {
        result.errors.messages.push_back(msg);
      }
    }
  });
  run_stage(result, "tlsh", [&] {
    if (!hasher::fuzzy_hash_file(result.tlsh, info)) {
      add_error(result.errors, extractor_error::hash_failed, "TLSH fuzzy hashing failed");
      for (const auto& msg : hasher::get_fuzzy_hash_error_messages(result.tlsh)) {
        result.errors.messages.push_back(msg);
      }
    }
  });

  return run_pipeline(result, info, options, job, started);
}

std::vector<stage_errors_t> recover_errors(const extraction_result_t& result) {
  std::vector<stage_errors_t> stages;
  auto push = [&](const char* name, const std::vector<std::string>& messages) {
    if (messages.empty()) return;
    stages.push_back({ name, messages });
  };

  if (result.input_errors.flags != extractor_error::none)
    push("input", result.input_errors.messages);
  if (result.sha256.errors.flags != hash_error::none)
    push("hashing-sha256", result.sha256.errors.messages);
  if (result.tlsh.errors.flags != hash_error::none)
    push("hashing-tlsh", result.tlsh.errors.messages);
  if (result.guards.errors.flags != extractor_error::none)
    push("guards", result.guards.errors.messages);
  if (result.elf.errors.flags != extractor_error::none)
    push("elf", result.elf.errors.messages);
  if (result.pe.errors.flags != extractor_error::none)
    push("pe", result.pe.errors.messages);
  if (result.pe.iat.errors.flags != extractor_error::none)
    push("iat", result.pe.iat.errors.messages);
  if (result.elf.got.errors.flags != extractor_error::none)
    push("elf-got", result.elf.got.errors.messages);
  if (result.got.errors.flags != extractor_error::none)
    push("got", result.got.errors.messages);
  if (result.sections.errors.flags != extractor_error::none)
    push("sections", result.sections.errors.messages);
  if (result.strings.errors.flags != extractor_error::none)
    push("strings", result.strings.errors.messages);
  if (result.histogram.errors.flags != extractor_error::none)
    push("histogram", result.histogram.errors.messages);
  if (result.packer.errors.flags != extractor_error::none)
    push("packer", result.packer.errors.messages);
  if (result.opcodes.errors.flags != extractor_error::none)
    push("opcodes", result.opcodes.errors.messages);
  if (result.debug_symbols.errors.flags != extractor_error::none)
    push("debug", result.debug_symbols.errors.messages);
  if (result.signature.errors.flags != extractor_error::none)
    push("signature", result.signature.errors.messages);
  if (result.capa.errors.flags != extractor_error::none)
    push("capa", result.capa.errors.messages);
  if (result.hexdump.errors.flags != extractor_error::none)
    push("hexdump", result.hexdump.errors.messages);
  if (result.cminer.errors.flags != extractor_error::none)
    push("cminer", result.cminer.errors.messages);
  if (!result.yara.errors.empty())
    push("yara", result.yara.errors);

  return stages;
}

// ---------------------------------------------------------------------------
// Per-result error helpers
// ---------------------------------------------------------------------------

bool has_errors(const guard_info_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const guard_info_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const elf_sections_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const elf_sections_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const pe_sections_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const pe_sections_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const iat_result_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const iat_result_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const got_result_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const got_result_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const sections_result_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const sections_result_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const strings_result_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const strings_result_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const byte_histogram_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const byte_histogram_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const packer_detection_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const packer_detection_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const opcode_stats_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const opcode_stats_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const debug_symbols_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const debug_symbols_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const signature_info_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const signature_info_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const capa_result_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const capa_result_t& result) {
  return get_error_messages(result.errors);
}

bool has_errors(const extraction_result_t& result) { return has_errors(result.errors); }
std::vector<std::string> get_error_messages(const extraction_result_t& result) {
  return get_error_messages(result.errors);
}

} // namespace extractor