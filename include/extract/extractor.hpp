#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "capa_runner.hpp"
#include "file_analyzer.hpp"
#include "file_hasher.hpp"
#include "yara_scanner.hpp"

namespace extractor {

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

enum class extractor_error : std::uint32_t {
  none               = 0,
  invalid_input      = 1u << 0,
  invalid_path       = 1u << 1,
  empty_file         = 1u << 2,
  read_failed        = 1u << 3,
  parse_failed       = 1u << 4,
  capstone_failed    = 1u << 5,
  unsupported_format = 1u << 6,
  no_code_section    = 1u << 7,
  no_strings         = 1u << 8,
  no_debug_symbols   = 1u << 9,
  hash_failed        = 1u << 10,
  no_signature       = 1u << 11,
  no_guards          = 1u << 12,
  capa_not_found     = 1u << 13,
  capa_failed        = 1u << 14,
  capa_timeout       = 1u << 15,
  hexdump_read_failed = 1u << 16,
  cminer_not_found   = 1u << 19,
  cminer_failed      = 1u << 20,
  cminer_timeout     = 1u << 21,
};

inline constexpr extractor_error operator|(extractor_error a, extractor_error b) {
  return static_cast<extractor_error>(
      static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}

inline constexpr extractor_error operator&(extractor_error a, extractor_error b) {
  return static_cast<extractor_error>(
      static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}

inline extractor_error& operator|=(extractor_error& a, extractor_error b) {
  a = a | b;
  return a;
}

inline constexpr bool has_error(extractor_error flags, extractor_error e) {
  return (static_cast<std::uint32_t>(flags) &
          static_cast<std::uint32_t>(e)) != 0;
}

inline constexpr extractor_error soft_errors =
    extractor_error::no_strings | extractor_error::no_debug_symbols |
    extractor_error::no_signature | extractor_error::no_guards |
    extractor_error::no_code_section | extractor_error::unsupported_format |
    extractor_error::capa_not_found | extractor_error::capa_failed |
    extractor_error::capa_timeout | extractor_error::hexdump_read_failed |
    extractor_error::cminer_not_found | extractor_error::cminer_failed |
    extractor_error::cminer_timeout;

inline constexpr bool has_hard_error(extractor_error flags) {
  return (static_cast<std::uint32_t>(flags) &
          ~static_cast<std::uint32_t>(soft_errors)) != 0;
}

struct error_type_t {
  extractor_error          flags = extractor_error::none;
  std::vector<std::string> messages;
  std::string              details;
};

void add_error(error_type_t& errors, extractor_error error,
               const std::string& detail);

bool has_errors(const error_type_t& errors);
std::vector<std::string> get_error_messages(const error_type_t& errors);

// ---------------------------------------------------------------------------
// Compilation guards / exploit mitigations
// ---------------------------------------------------------------------------

struct guard_info_t {
  error_type_t errors;

  std::string format;

  // --- PE (DllCharacteristics) ---
  bool has_aslr            = false;
  bool has_high_entropy_va = false;
  bool has_dep             = false;
  bool has_nx              = false;
  bool has_force_integrity = false;
  bool has_isolation       = false;
  bool has_seh             = false;
  bool has_no_bind         = false;
  bool has_wdm_driver      = false;
  bool has_guard_cf        = false;

  bool has_cet_compat                         = false;
  bool cet_strict_mode                        = false;
  bool cet_set_context_ip_validation_relaxed  = false;
  bool cet_dynamic_apis_allow_in_proc         = false;

  std::uint16_t dll_characteristics_raw = 0;

  // --- ELF (GNU Property Notes) ---
  bool has_shstk = false;
  bool has_ibt   = false;
  std::uint32_t x86_features_raw = 0;

  std::vector<std::string> notes;

  bool has_stack_cookie = false;
  bool has_safe_seh     = false;

  bool has_pie          = false;
  bool has_relro        = false;
  bool has_full_relro   = false;
  bool has_stack_canary = false;
  bool has_fortify      = false;
  bool has_rpath        = false;
  bool executable_stack = false;
  bool has_bti          = false;
  bool has_pac          = false;
  std::uint32_t aarch64_features_raw = 0;

  std::size_t mitigations_enabled = 0;
  std::size_t mitigations_checked = 0;
};

bool extract_guard_info(guard_info_t& result,
                        const analyzer::file_info_t& info);

// ---------------------------------------------------------------------------
// ELF sections
// ---------------------------------------------------------------------------

struct elf_section_t {
  std::string   name;
  std::uint64_t virtual_address = 0;
  std::uint64_t size            = 0;
  double        entropy         = 0.0;
  double        chi2            = 0.0;
  std::string   type;
  std::string   flags;

  file_hash_t   sha256{};
  fuzzy_hash_t  tlsh{};

  bool readable   = false;
  bool writable   = false;
  bool executable = false;
};

// ---------------------------------------------------------------------------
// GOT / PLT entries — ELF and Mach-O
// ---------------------------------------------------------------------------

struct got_entry_t {
  std::string   name;                  // symbol name (may be empty for locals)
  std::string   library;               // DT_NEEDED / dylib that provides the symbol

  std::uint64_t slot_address  = 0;     // VA of the GOT/pointer slot itself
  std::uint64_t slot_offset   = 0;     // FILE offset of the slot (0 if unknown)
  std::uint64_t initial_value = 0;     // raw 32/64-bit value stored in the file

  std::uint64_t plt_stub_address = 0;  // ELF only: VA of the PLT stub
  std::uint64_t stub_address     = 0;  // Mach-O only: VA of the __stubs entry

  std::uint64_t reloc_address = 0;
  std::uint64_t reloc_addend  = 0;
  std::string   reloc_type;

  std::string   binding;               // "GLOBAL" | "WEAK" | "LOCAL" (ELF)
  bool          is_lazy = false;       // Mach-O lazy pointer
  bool          is_weak = false;
};

struct got_result_t {
  error_type_t             errors;
  std::vector<got_entry_t> entries;

  std::string format;                  // "ELF" | "MachO"
  std::string architecture;

  std::size_t slot_count  = 0;
  std::size_t named_count = 0;
  std::size_t plt_count   = 0;
  std::size_t lazy_count  = 0;
  bool        truncated   = false;

  std::uint64_t got_lowest_slot  = 0;
  std::uint64_t got_highest_slot = 0;

  std::vector<std::string> sections;
};

struct elf_sections_t {
  error_type_t               errors;
  std::string                machine;
  std::string                file_type;
  std::uint64_t              entrypoint = 0;
  std::vector<elf_section_t> sections;

  bool                     is_pie = false;
  std::string              interpreter;
  std::vector<std::string> needed_libraries;

  got_result_t             got;        // added
};

bool extract_elf_sections(elf_sections_t& result,
                          const analyzer::file_info_t& info);

// ---------------------------------------------------------------------------
// PE sections
// ---------------------------------------------------------------------------

struct pe_section_t {
  std::string   name;
  std::uint64_t virtual_address = 0;
  std::uint64_t virtual_size    = 0;
  std::uint64_t raw_size        = 0;
  std::uint64_t raw_offset      = 0;
  std::uint64_t raw_end         = 0;
  std::uint64_t size            = 0;
  double        entropy         = 0.0;
  double        chi2            = 0.0;
  std::string   characteristics;

  file_hash_t   sha256{};
  fuzzy_hash_t  tlsh{};

  bool readable   = false;
  bool writable   = false;
  bool executable = false;
};

// ---------------------------------------------------------------------------
// PE IAT / import table entries
// ---------------------------------------------------------------------------

struct iat_entry_t {
  std::string   dll;
  std::string   name;
  std::uint16_t hint        = 0;
  std::uint16_t ordinal     = 0;
  bool          is_ordinal  = false;

  std::uint64_t iat_rva     = 0;
  std::uint64_t iat_value   = 0;
  std::uint64_t int_rva     = 0;
  std::uint64_t ilt_rva     = 0;
  std::uint64_t iat_base    = 0;
  std::uint32_t timestamp   = 0;
  std::uint32_t forwarder   = 0;

  bool          is_delay    = false;
};

struct iat_result_t {
  error_type_t             errors;
  std::vector<iat_entry_t> entries;

  std::size_t dll_count            = 0;
  std::size_t named_import_count   = 0;
  std::size_t ordinal_import_count = 0;
  std::size_t delay_dll_count      = 0;
  std::size_t delay_import_count   = 0;
  bool        truncated            = false;

  std::uint64_t iat_lowest_rva  = 0;
  std::uint64_t iat_highest_rva = 0;
};

struct pe_export_entry_t {
  std::string   name;
  std::uint16_t ordinal = 0;
  std::uint64_t rva = 0;
  std::uint32_t address = 0;
  std::uint32_t function_rva = 0;
  bool          is_extern = false;
  bool          is_forwarded = false;
  std::string   forwarder_library;
  std::string   forwarder_function;
};

struct pe_export_table_t {
  bool present = false;
  std::string name;
  std::uint32_t timestamp = 0;
  std::uint16_t major_version = 0;
  std::uint16_t minor_version = 0;
  std::uint32_t ordinal_base = 0;
  std::uint32_t export_addr_table_rva = 0;
  std::uint32_t export_addr_table_count = 0;
  std::uint32_t names_addr_table_rva = 0;
  std::uint32_t names_addr_table_count = 0;
  std::uint32_t ordinal_addr_table_rva = 0;
  std::size_t named_count = 0;
  std::size_t forwarded_count = 0;
  std::size_t external_count = 0;
  std::vector<pe_export_entry_t> entries;
};

struct pe_overlay_signature_t {
  std::string   format;
  std::string   description;
  std::uint64_t offset = 0;          // absolute file offset
  std::uint64_t relative_offset = 0; // offset from overlay start
  std::uint64_t size = 0;             // available bytes from signature to overlay end
  double        confidence = 0.0;
};

struct pe_overlay_t {
  bool present = false;
  bool truncated = false;
  std::uint64_t offset = 0;
  std::uint64_t size = 0;
  std::string magic_hex;
  std::string magic_ascii;
  std::string sha256;
  double entropy = 0.0;
  double chi2 = 0.0;
  std::vector<pe_overlay_signature_t> signatures;
  std::vector<std::uint8_t> data;
};

struct pe_security_directory_t {
  bool                     present = false;
  std::uint64_t            file_offset = 0;
  std::uint64_t            size = 0;
  std::uint64_t            end_offset = 0;
  bool                     within_file = false;
  bool                     overlaps_section = false;
  bool                     inside_section_overlay = false;
  bool                     valid_range = false;
  std::size_t              certificate_count = 0;
  std::vector<std::string> warnings;
};

struct pe_sections_t {
  error_type_t              errors;
  std::string               machine;
  std::string               characteristics;
  std::uint64_t             entrypoint = 0;
  std::vector<pe_section_t> sections;

  std::uint32_t            timestamp = 0;
  std::string              subsystem;
  std::string              imphash;
  std::string              entry_section;
  std::uint64_t            overlay_size = 0;
  std::uint64_t            file_size = 0;
  std::uint64_t            last_section_end = 0;
  std::uint64_t            computed_overlay_start = 0;
  std::uint64_t            computed_overlay_end = 0;
  std::uint64_t            computed_overlay_size = 0;
  std::uint64_t            overlay_after_security_start = 0;
  std::uint64_t            overlay_after_security_end = 0;
  std::uint64_t            overlay_after_security_size = 0;
  bool                     has_computed_overlay = false;
  bool                     has_overlay_after_security = false;
  bool                     overlay_size_matches = false;
  bool                     is_dll = false;
  std::vector<std::string> imported_dlls;
  std::size_t              import_function_count = 0;
  std::size_t              export_count = 0;

  pe_export_table_t export_table;
  pe_overlay_t overlay;
  pe_security_directory_t security_directory;
  iat_result_t             iat;        // added
};

bool extract_pe_sections(pe_sections_t& result,
                         const analyzer::file_info_t& info);

bool extract_iat(iat_result_t& result,
                 const analyzer::file_info_t& info,
                 std::size_t max_entries = 200000);

// Unified entry point for GOT / PLT across ELF and Mach-O.
bool extract_got(got_result_t& result,
                 const analyzer::file_info_t& info,
                 std::size_t max_entries = 200000);

// ---------------------------------------------------------------------------
// Generic sections
// ---------------------------------------------------------------------------

struct section_info_t {
  std::string   name;
  std::uint64_t virtual_address = 0;
  std::uint64_t size            = 0;
  double        entropy         = 0.0;
  double        chi2            = 0.0;

  file_hash_t   sha256{};
  fuzzy_hash_t  tlsh{};
};

struct sections_result_t {
  error_type_t               errors;
  std::vector<section_info_t> sections;
};

bool extract_sections(sections_result_t& result,
                      const analyzer::file_info_t& info);

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

struct string_entry_t {
  std::string   value;
  std::uint64_t offset = 0;

  std::string   section;
  std::string   encoding;
};

struct strings_result_t {
  error_type_t                errors;
  std::vector<string_entry_t> strings;

  std::size_t ascii_count = 0;
  std::size_t utf16_count = 0;
  bool        truncated   = false;
};

bool extract_strings(strings_result_t& result,
                     const analyzer::file_info_t& info,
                     std::size_t min_length = 4,
                     std::size_t max_strings = 500000);

// ---------------------------------------------------------------------------
// Byte histogram (whole file)
// ---------------------------------------------------------------------------

struct byte_histogram_t {
  error_type_t  errors;
  std::uint64_t counts[256]      = {};
  double        frequencies[256] = {};

  std::uint64_t total_bytes   = 0;
  double        entropy       = 0.0;
  double        chi2          = 0.0;
  double        mean          = 0.0;
  double        stddev        = 0.0;

  std::uint8_t most_common_byte  = 0;
  std::uint8_t least_common_byte = 0;
  std::size_t  nonzero_bins      = 0;
  std::size_t  zero_bytes        = 0;

  // EMBER2024 thrember-compatible ML vectors (normalized, sum == 1).
  // ember_histogram[i] = counts[i] / total_bytes (ByteHistogram.process_raw_features).
  // ember_byteentropy[Hbin * 16 + (b >> 4)] = joint byte/entropy histogram
  // (ByteEntropyHistogram: window=2048, step=1024, 16x16, normalized by sum).
  double ember_histogram[256]   = {};
  double ember_byteentropy[256] = {};
};

bool extract_byte_histogram(byte_histogram_t& result,
                            const analyzer::file_info_t& info);

struct packer_detection_t {
  error_type_t             errors;
  bool                     packed = false;
  std::vector<std::string> reasons;

  int         score             = 0;
  std::string confidence;
  std::string suspected_packer;
  double      overall_entropy   = 0.0;
};

bool detect_if_packed(packer_detection_t& result,
                      const analyzer::file_info_t& info);

// ---------------------------------------------------------------------------
// Opcode stats
// ---------------------------------------------------------------------------

struct mnemonic_count_t {
  std::string   mnemonic;
  std::uint64_t count     = 0;
  double        frequency = 0.0;
};

struct opcode_stats_t {
  error_type_t  errors;
  std::string   architecture;
  std::uint64_t total_instructions = 0;
  std::uint32_t counts[256]        = {};
  double        frequencies[256]   = {};

  std::uint64_t code_bytes    = 0;
  std::uint64_t decoded_bytes = 0;
  std::uint64_t invalid_bytes = 0;
  double        coverage      = 0.0;
  std::vector<mnemonic_count_t> top_mnemonics;
};

bool generate_opcode_stats(opcode_stats_t& result,
                           const analyzer::file_info_t& info);

// ---------------------------------------------------------------------------
// Debug symbols
// ---------------------------------------------------------------------------

struct debug_symbol_t {
  std::string   name;
  std::string   demangled_name;
  std::string   type;
  std::string   binding;
  std::string   visibility;
  std::string   version;
  std::uint64_t address   = 0;
  std::uint64_t size      = 0;
  bool          imported  = false;
  bool          exported  = false;
  bool          undefined = false;

  std::string   source;
};

struct debug_symbols_t {
  error_type_t                errors;
  std::string                 format;
  bool                        has_debug_symbols  = false;
  bool                        has_debug_sections = false;
  bool                        stripped           = false;
  std::string                 pdb_filename;
  std::string                 pdb_guid;
  std::uint32_t               pdb_age            = 0;
  std::uint32_t               pdb_timestamp      = 0;
  std::vector<std::string>    debug_sections;
  std::vector<debug_symbol_t> symbols;

  std::size_t symbol_count = 0;
  bool        truncated    = false;
};

bool extract_debug_symbols(debug_symbols_t& result,
                           const analyzer::file_info_t& info,
                           std::size_t max_symbols = 200000);

// ---------------------------------------------------------------------------
// Signature info
// ---------------------------------------------------------------------------

struct signature_info_t {
  error_type_t errors;

  bool        has_signature  = false;
  bool        is_signed      = false;
  bool        is_valid       = false;
  std::size_t num_signatures = 0;

  std::string format;
  std::string signer;
  std::string issuer;
  std::string digest_algorithm;

  std::vector<std::string> details;

  std::string verification;
};

bool extract_signature_info(signature_info_t& result,
                            const analyzer::file_info_t& info);

// ---------------------------------------------------------------------------
// capa
// ---------------------------------------------------------------------------

using capa_options_t = capa::options;

struct capa_result_t {
  error_type_t errors;

  bool        attempted  = false;
  bool        from_cache = false;
  double      seconds    = 0.0;
  int         exit_code  = 0;

  std::string version;
  std::string format, arch, os;
  std::string backend;

  std::size_t rules_matched = 0;
  std::size_t library_rules = 0;
  std::vector<capa::capability_t> capabilities;

  std::vector<std::string> attack_ids;
  std::vector<std::string> mbc_ids;
  std::vector<std::pair<std::string, std::size_t>> categories;

  std::vector<std::string> warnings;
  std::string              stderr_tail;
};

bool extract_capa(capa_result_t& result,
                  const analyzer::file_info_t& info,
                  const capa_options_t& options = {});

// Hexdump of the head of the file, produced natively.
//
// This used to shell out to xxd (XXD_PATH, then a vendored tools/bin/xxd.exe,
// then bare "xxd" on PATH, then a WSL fallback) and keep the formatted text.
// Reading the bytes here instead is simpler and strictly better on every axis
// that mattered:
//
//   * no external tool to locate, vendor or ship - the vendored xxd.exe alone
//     was a 63 KiB binary committed to the tree, and on a machine with no
//     vim/neovim and no WSL the whole feature silently produced nothing;
//   * no -g/-c/-l flag dialect to get wrong (xxd and hexdump share no flags);
//   * the dashboard needs bytes, not text, so it had to re-parse the formatted
//     output back into numbers. `bytes` is exactly what it wanted.
//
// The bound is on bytes, not on rendered text, so `truncated` means what it
// says: the sample is larger than the window we kept.
struct hexdump_result_t {
  error_type_t errors;
  bool         attempted = false;
  bool         available = false;

  // Raw bytes starting at `base`. Bounded by the max_bytes argument.
  std::vector<std::uint8_t> bytes;
  std::uint64_t base = 0;          // file offset of bytes[0]
  std::size_t   total_bytes = 0;   // size of the whole file
  bool          truncated = false;  // total_bytes > bytes.size()
  std::size_t   bytes_per_row = 16;

  double seconds = 0.0;
};

bool extract_hexdump(hexdump_result_t& result,
                     const analyzer::file_info_t& info,
                     std::size_t max_bytes = 4096u);

// Cminer code-cave results. Cminer is a Linux CLI, so the extractor invokes the
// bundled executable through WSL and parses its structured cave report.
struct cminer_cave_t {
  std::string   section;
  std::uint64_t size = 0;
  std::uint64_t start_address = 0;
  std::uint64_t end_address = 0;
  std::uint64_t file_offset = 0;
};

struct cminer_result_t {
  error_type_t errors;
  bool         attempted = false;
  bool         available = false;
  bool         applicable = false;          // Cminer only analyzes PE files
  int          exit_code = -1;
  double       seconds = 0.0;
  std::size_t  minimum_cave_size = 300;
  std::uint64_t total_cave_bytes = 0;
  std::uint64_t largest_cave_bytes = 0;
  std::vector<cminer_cave_t> caves;
  std::string command;
  std::string output;
  std::string stderr_tail;
};

bool extract_cminer(cminer_result_t& result,
                    const analyzer::file_info_t& info,
                    std::size_t minimum_cave_size = 300);

// ---------------------------------------------------------------------------
// Extraction result
// ---------------------------------------------------------------------------

struct stage_timing_t {
  std::string stage;
  double      seconds = 0.0;
};

struct extraction_result_t {
  error_type_t        errors;

  file_hash_t         sha256{};
  fuzzy_hash_t        tlsh{};

  guard_info_t        guards;
  elf_sections_t      elf;
  pe_sections_t       pe;
  sections_result_t   sections;
  strings_result_t    strings;
  byte_histogram_t    histogram;
  packer_detection_t  packer;
  opcode_stats_t      opcodes;
  debug_symbols_t     debug_symbols;
  signature_info_t    signature;

  got_result_t        got;             // ELF / Mach-O GOT / PLT
  capa_result_t       capa;
  hexdump_result_t      hexdump;
  cminer_result_t      cminer;
  yara_scanner::result_t yara;

  error_type_t               input_errors;
  std::vector<stage_timing_t> timings;
  double                     total_seconds = 0.0;
};

struct analysis_options_t {
  std::size_t min_string_length = 4;
  std::size_t max_strings       = 500000;
  std::size_t max_symbols       = 200000;
  std::size_t max_iat_entries   = 200000;
  std::size_t max_got_entries   = 200000;
  std::size_t cminer_min_cave_size = 300;

  bool           run_capa      = false;
  bool           capa_required = false;
  capa_options_t capa;
};

bool analyze(extraction_result_t& result,
             const analyzer::file_info_t& info);

bool analyze(extraction_result_t& result,
             const analyzer::file_info_t& info,
             const analysis_options_t& options);

bool analyze_with_hashes(extraction_result_t& result,
                         analyzer::file_info_t& info);

bool analyze_with_hashes(extraction_result_t& result,
                         analyzer::file_info_t& info,
                         const analysis_options_t& options);

struct stage_errors_t {
  std::string              stage;
  std::vector<std::string> messages;
};

std::vector<stage_errors_t> recover_errors(const extraction_result_t& result);

double calculate_entropy(const std::uint8_t* bytes, std::size_t size);
double calculate_chi2(const std::uint8_t* bytes, std::size_t size);

bool has_errors(const guard_info_t& result);
std::vector<std::string> get_error_messages(const guard_info_t& result);

bool has_errors(const elf_sections_t& result);
std::vector<std::string> get_error_messages(const elf_sections_t& result);

bool has_errors(const pe_sections_t& result);
std::vector<std::string> get_error_messages(const pe_sections_t& result);

bool has_errors(const iat_result_t& result);
std::vector<std::string> get_error_messages(const iat_result_t& result);

bool has_errors(const got_result_t& result);
std::vector<std::string> get_error_messages(const got_result_t& result);

bool has_errors(const sections_result_t& result);
std::vector<std::string> get_error_messages(const sections_result_t& result);

bool has_errors(const strings_result_t& result);
std::vector<std::string> get_error_messages(const strings_result_t& result);

bool has_errors(const byte_histogram_t& result);
std::vector<std::string> get_error_messages(const byte_histogram_t& result);

bool has_errors(const packer_detection_t& result);
std::vector<std::string> get_error_messages(const packer_detection_t& result);

bool has_errors(const opcode_stats_t& result);
std::vector<std::string> get_error_messages(const opcode_stats_t& result);

bool has_errors(const debug_symbols_t& result);
std::vector<std::string> get_error_messages(const debug_symbols_t& result);

bool has_errors(const signature_info_t& result);
std::vector<std::string> get_error_messages(const signature_info_t& result);

bool has_errors(const capa_result_t& result);
std::vector<std::string> get_error_messages(const capa_result_t& result);

bool has_errors(const extraction_result_t& result);
std::vector<std::string> get_error_messages(const extraction_result_t& result);

} // namespace extractor