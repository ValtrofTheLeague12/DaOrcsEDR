// radare2_runner.hpp

#pragma once

// Runs radare2 inside WSL (or natively on Linux) and extracts:
//   * JSON metadata              (rabin2 -Ij / -Sj / -ij / -sj / -ej)
//   * Graphviz .dot files        (r2 -c "agfd" / -c "agCd")
//   * Function lists             (r2 -c "aflj")
//   * Raw assembly               (r2 -c "pdfj @@f"  -> JSON, then rendered)
//   * Per-section .dot graphs    (r2 -c "agfd" per function, grouped by section)
//   * IAT/GOT call-site assembly (r2 -c "axtj" + "pdfj" over resolved xrefs)
//
// Paths are translated from Windows to WSL ("C:\x" -> "/mnt/c/x") before being
// passed to the tools, and outputs are written atomically and in binary mode on
// the Windows side (no CRLF translation).
//
// Raw ASM is captured as r2 JSON (`pdfj @@f`) as the source of truth, so that
// per-function boundaries, per-instruction bytes, and per-instruction VAs are
// preserved exactly. A flat `.asm` file is rendered from that JSON as a
// convenience artifact; it is never parsed back.
//
// Graphviz rendering (dot.exe -> svg / png / pdf) is done via proc::run, so
// timeouts, output caps, and process-tree kill behave the same as every other
// external tool here.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace r2 {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

enum class status {
  ok,
  partial,            // some sub-operations failed, see result.errors
  file_missing,
  not_found,          // r2 / rabin2 not on PATH (inside WSL or natively)
  launch_failed,
  timed_out,
  output_too_large,
  exit_error,
  bad_output,
  write_failed,
};

const char* to_string(status s);

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

struct options {
  std::string executable     = "r2";      // r2 binary name or absolute path
  std::string rabin2         = "rabin2";  // rabin2 binary name or absolute path
  std::string wsl_distro;                 // empty = default WSL distro
  bool        use_wsl        = true;      // false: run natively (Linux builds)
  bool        quiet          = true;      // -q
  bool        analysis       = true;      // -A (aaa) before running commands
  int         threads        = 0;         // 0 = let r2 decide
  std::chrono::milliseconds timeout{300000};           // 5 min default
  std::size_t max_stdout_bytes = 256u * 1024u * 1024u;
  std::size_t max_stderr_bytes = 1u * 1024u * 1024u;
  bool        low_priority     = false;

  // Analysis determinism. These are applied as -e overrides so output is
  // reproducible across runs and across r2 versions where defaults differ.
  // Set `pin_analysis_config = false` to let r2 use its own defaults.
  bool        pin_analysis_config = true;
  int         anal_timeout_ms     = 120000;   // anal.timeout (ms)
  int         anal_bb_maxsize     = 0;        // anal.bb.maxsize (0 = leave unset)

  // Populated by the runner when a result is produced; left empty if
  // discovery failed. Filled from `r2 -v` / `rabin2 -v`.
  std::string r2_version;
  std::string rabin2_version;
};

// ---------------------------------------------------------------------------
// rabin2 metadata (JSON)
// ---------------------------------------------------------------------------

struct info_t {
  std::string arch;
  std::string bits;
  std::string bintype;      // "pe", "elf", "mach0", ...
  std::string endian;
  std::string machine;
  std::string os;
  std::string compiler;
  std::string stripped;
  std::string class_;       // "32" / "64"
  std::uint64_t baddr  = 0;
  std::uint64_t entry  = 0;
  std::uint64_t size   = 0;
  std::string file_hash_sha256;
  std::string file_hash_md5;
};

struct section_t {
  std::string name;
  std::uint64_t vaddr = 0;
  std::uint64_t paddr = 0;
  std::uint64_t size  = 0;
  std::string perms;        // "r-x" for executable code
  std::string type;
  double      entropy = 0.0;
};

struct symbol_t {
  std::string name;
  std::uint64_t vaddr = 0;
  std::string type;
  std::string bind;
  bool        import  = false;
  bool        export_ = false;
};

struct import_t {
  std::string library;
  std::string name;
  std::uint64_t plt     = 0;
  std::uint64_t ordinal = 0;
};

struct entrypoint_t {
  std::uint64_t vaddr = 0;
  std::uint64_t paddr = 0;
  std::string   name;
};

struct result_t {
  status        st = status::ok;
  std::string   error;
  double        seconds = 0.0;
  int           exit_code = 0;
  std::string   command_line;
  std::string   stderr_tail;

  info_t        info;
  std::vector<section_t>    sections;
  std::vector<symbol_t>     symbols;
  std::vector<import_t>     imports;
  std::vector<entrypoint_t> entrypoints;

  json          raw;
};

// Runs rabin2 once per flag (-I, -S, -s, -i, -e) and merges the JSON results.
// Each output is parsed as a single JSON document; merging never clobbers a
// non-empty field with an empty one from a later document.
result_t analyze_file(const std::string& sample, const options& opts = {});

// ---------------------------------------------------------------------------
// Function listing (r2 -c "aflj")
// ---------------------------------------------------------------------------

struct function_info_t {
  std::string   name;
  std::uint64_t offset  = 0;
  std::uint64_t size    = 0;
  std::uint64_t blocks  = 0;    // number of basic blocks
  bool          is_pure = false;
};

struct function_list_result_t {
  status        st = status::ok;
  std::string   error;
  double        seconds = 0.0;
  int           exit_code = 0;
  std::string   command_line;
  std::string   stderr_tail;
  std::vector<function_info_t> functions;
};

function_list_result_t list_functions(const std::string& sample,
                                      const options& opts = {});

// ---------------------------------------------------------------------------
// Raw assembly extraction (r2 -c "pdfj @@f")
//
// Source of truth is r2's JSON. The flat `.asm` file is rendered from it and
// must never be parsed back into structured data.
// ---------------------------------------------------------------------------

struct instruction_t {
  std::uint64_t offset = 0;   // instruction VA
  std::string   bytes;        // raw instruction bytes as hex ("4889e5")
  std::string   disasm;       // mnemonic + operands
  std::string   type;         // r2 "type" field, e.g. "mov", "call", "ret"
  std::string   section;      // containing radare2/rabin2 section, or <unmapped>
  bool          valid = true; // r2 produced a usable disasm string

  // Resolved control-flow target (call / jmp / conditional jmp). 0 = none.
  std::uint64_t target = 0;
  // Human-readable label for `target` (function name or "dll!import"),
  // empty when unresolved. targets_import marks import thunks.
  std::string   target_label;
  bool          targets_import = false;
};

struct section_nop_stat_t {
  std::string   section;
  std::size_t   instructions = 0;
  std::size_t   nop_count = 0;

  double nop_percent() const {
    return instructions == 0 ? 0.0
                             : (100.0 * static_cast<double>(nop_count) / static_cast<double>(instructions));
  }
};

struct raw_function_t {
  std::string   name;
  std::uint64_t offset = 0;   // function VA
  std::uint64_t size   = 0;   // function size reported by r2
  std::uint64_t n_instr = 0;
  std::size_t   nop_count = 0;
  bool          truncated = false;  // pdf hit anal.bb.maxsize / anal.timeout
  std::vector<instruction_t> instructions;
  std::string   error;        // per-function r2 error, if any
};

struct raw_asm_options {
  // If output_path is non-empty it wins; otherwise the flat .asm is written
  // to <out_dir>/<stem>_functions.asm. Set emit_asm=false to skip writing it
  // while still returning the structured JSON.
  std::string output_path;
  bool        emit_asm         = true;

  // If json_output_path is non-empty, the raw r2 JSON is also written there.
  // If empty, the runner writes <out_dir>/<stem>_functions.json.
  std::string json_output_path;

  // Filtering. Filtering by name is intentionally NOT the default: the
  // majority of code in a stripped binary is unnamed, and dropping it is
  // rarely what the caller wants. Provide a predicate instead of a name regex.
  std::function<bool(const function_info_t&)> include_function;  // {} = include all

  // Cap on the number of functions disassembled (batched `pdfj @ <offset>`).
  std::size_t max_functions = 2000;

  // Formatting for the rendered flat .asm (does not affect JSON).
  bool include_addresses       = true;   // prefix each instr line with its VA
  bool include_function_header = true;   // emit ;;; function: name @ 0x... banners
  bool include_raw_bytes       = false;  // append "; bytes=..." per instruction
  bool include_target_labels   = true;   // append "; -> label" for resolved targets
};

struct raw_asm_result_t {
  status        st = status::ok;
  std::string   error;
  double        seconds = 0.0;

  std::string   asm_path;         // flat .asm (empty if emit_asm=false)
  std::size_t   asm_bytes = 0;    // exact byte size of the file on disk
  std::string   json_path;        // raw r2 JSON (empty if not written)

  std::vector<raw_function_t> functions;

  // Counters. functions_dumped == functions.size(); the rest let the caller
  // detect truncation and silent per-function failures.
  std::size_t   functions_requested = 0;  // entries in aflj before filtering
  std::size_t   functions_dumped    = 0;  // entries actually written
  std::size_t   functions_truncated = 0;  // pdf reported truncation
  std::size_t   instructions_total  = 0;
  std::size_t   nop_total           = 0;
  std::vector<section_nop_stat_t> section_nop_stats;  // requires section metadata

  std::vector<std::pair<std::string, std::string>> errors;  // {function, msg}

  std::string   command_line;   // includes the -e overrides actually used
  std::string   stderr_tail;
  int           exit_code = 0;

  // Provenance for reproducibility.
  std::string   r2_version;
};

raw_asm_result_t dump_function_assembly(const std::string& sample,
                                        const std::string& out_dir,
                                        const std::string& stem,
                                        const options& opts = {},
                                        const raw_asm_options& dump = {});

// ---------------------------------------------------------------------------
// .dot extraction (r2 -c "agfd" / "agCd")
// ---------------------------------------------------------------------------

struct dot_options {
  bool          whole_program = false;    // false = entry function only
  std::string   function;                 // "" = current seek (entrypoint)
  std::uint64_t address = 0;              // 0 = use function name or entrypoint
  std::chrono::milliseconds timeout{0};   // 0 = use options::timeout
};

struct dot_result_t {
  status        st = status::ok;
  std::string   error;
  double        seconds = 0.0;
  int           exit_code = 0;
  std::string   command_line;
  std::string   stderr_tail;
  std::size_t   bytes_written = 0;
  std::string   raw;                      // the DOT source that was written
};

dot_result_t extract_dot(const std::string& sample,
                         const std::string& out_path,
                         const options& opts = {},
                         const dot_options& dot = {});

// ---------------------------------------------------------------------------
// Per-section .dot assembly (r2 -c "agfd" per function, grouped by section)
//
// One .dot file per executable section. Each file contains the basic-block
// CFG of every function whose start address falls inside that section's
// [vaddr, vaddr+size) range. Node IDs are namespaced per function before
// merging so identically-numbered nodes in different functions don't collide.
//
// Output: <out_dir>/<stem>_section_<sanitized_name>.dot
// ---------------------------------------------------------------------------

struct section_dot_options {
  std::string output_dir;                       // "" = <out_dir>
  std::string filename_pattern = "{stem}_section_{section}.dot";
  bool        executable_only  = true;          // only sections with 'x' in perm
  std::size_t max_functions_per_section = 5000;
  std::chrono::milliseconds per_section_timeout{0};  // 0 = use options::timeout
  bool        skip_empty = true;                // don't write a .dot with no nodes
};

struct section_dot_file_t {
  std::string section;
  std::string path;
  std::size_t bytes = 0;
  std::size_t functions = 0;
  bool        empty = false;
};

struct section_dot_result_t {
  status        st = status::ok;
  std::string   error;
  double        seconds = 0.0;
  std::vector<section_dot_file_t> files;
  std::vector<std::pair<std::string, std::string>> errors;  // {section, message}
  std::size_t   sections_considered = 0;
  std::size_t   sections_written = 0;
  std::string   command_line;
};

section_dot_result_t dump_section_dots(const std::string& sample,
                                       const std::string& out_dir,
                                       const std::string& stem,
                                       const options& opts = {},
                                       const section_dot_options& dump = {});

// ---------------------------------------------------------------------------
// Graphviz rendering (dot.exe -> svg / png / pdf / ...)
//
// Renders .dot files produced above (or any DOT source) via the external
// `dot` binary. Uses proc::run, so timeouts, output caps, and process-tree
// kill all behave the same as every other external tool here.
//
// Returns "" on success, otherwise a human-readable error string.
// ---------------------------------------------------------------------------

// Windows: "C:\Program Files\Graphviz\bin\dot.exe", then the (x86) path,
// then "dot" from PATH. Returns "" if nothing is found.
std::string default_dot();

// Renders `in_dot` to `out_path` in `format` ("svg" | "png" | "pdf" | ...).
// Writes to out_path + ".tmp" first, then renames, so a failed or killed
// dot never leaves a half-written output.
std::string render_dot(const std::string& dot_exe,
                       const std::string& in_dot,
                       const std::string& out_path,
                       const std::string& format = "svg");

// Renders every non-empty .dot in `sections` next to its source file.
// Returns one {section_name, error} pair per failure; empty == all ok.
std::vector<std::pair<std::string, std::string>>
render_section_dots(const section_dot_result_t& sections,
                    const std::string& dot_exe = {},
                    const std::string& format  = "svg");

// ---------------------------------------------------------------------------
// IAT / GOT call-site assembly (r2 -c "axtj" + "pdfj" over resolved xrefs)
//
// `targets` are the absolute virtual addresses of the import slots:
//   PE:    image_base + iat_rva   (r2 loads the PE at its preferred image base)
//   ELF:   got_entry_t::slot_address
//   MachO: got_entry_t::slot_address
//
// For each target, the runner resolves cross-references with `axtj`, maps
// every xref to its enclosing function via `aflj`, and disassembles those
// functions with `pdfj @ <fn_offset>`. The output contains only the functions
// that actually call into the IAT/GOT — no other code.
//
// The rendered .asm is derived from `pdfj` JSON, same as dump_function_assembly.
// ---------------------------------------------------------------------------

struct xref_asm_options {
  std::string output_path;               // "" = <out_dir>/<stem>_iat_calls.asm
  std::string json_output_path;          // "" = <out_dir>/<stem>_iat_calls.json
  std::size_t max_slots = 2000;          // cap on the number of input targets
  std::size_t max_functions = 500;       // cap on distinct functions dumped
  bool        dedup_functions = true;    // don't dump the same function twice
  bool        include_addresses = true;  // prefix every line with the VA
  bool        include_function_header = true;
  bool        include_raw_bytes = false;
};

struct xref_asm_result_t {
  status        st = status::ok;
  std::string   error;
  double        seconds = 0.0;
  std::string   path;
  std::size_t   bytes = 0;
  std::string   json_path;

  std::size_t   slots_input = 0;         // targets actually queried
  std::size_t   slots_with_xrefs = 0;    // slots that had at least one xref
  std::size_t   xrefs_found = 0;         // distinct call sites after dedup
  std::size_t   functions_dumped = 0;    // distinct enclosing functions written
  std::size_t   functions_truncated = 0;
  std::size_t   instructions_total = 0;

  std::vector<std::pair<std::string, std::string>> errors;

  std::string   command_line;
  std::string   stderr_tail;
  int           exit_code = 0;
  std::string   r2_version;
};

xref_asm_result_t dump_xref_calls(const std::string& sample,
                                  const std::string& out_dir,
                                  const std::string& stem,
                                  const std::vector<std::uint64_t>& targets,
                                  const options& opts = {},
                                  const xref_asm_options& dump = {});

// ---------------------------------------------------------------------------
// Bulk extraction
// ---------------------------------------------------------------------------

struct bulk_file_t {
  std::string path;
  std::size_t bytes = 0;
  std::string kind;   // "callgraph" | "entry" | "asm" | "asm_json"
                      // | "section:<name>"
};

struct bulk_result_t {
  status        st = status::ok;
  double        seconds = 0.0;
  std::vector<bulk_file_t>     files;
  std::vector<function_info_t> functions;
  std::size_t                  nop_total = 0;
  std::vector<section_nop_stat_t> section_nop_stats;
  std::vector<std::pair<std::string, std::string>> errors;
};

// under out_dir, and collects the function list.
bulk_result_t extract_all(const std::string& sample,
                          const std::string& out_dir,
                          const std::string& stem,
                          const options& opts = {});

std::string find_executable(const options& opts = {});
std::string find_rabin2(const options& opts = {});
std::string version(const options& opts = {});
std::string rabin2_version(const options& opts = {});

}  // namespace r2