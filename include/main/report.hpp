#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "console.hpp"          // file_analyzer / extractor / capa / yara types
#include "cti.hpp"
#include "ml_api.hpp"
#include "radare2_runner.hpp"
#include "secret_store.hpp"

// ---------------------------------------------------------------------------
// Report vocabulary
// ---------------------------------------------------------------------------
// The terminal report and the PDCurses results browser consume the same text:
// the browser captures std::cout and re-colours it by pattern (see
// src/ui/curses_ui.cpp), so every line printed here is also a line that file
// has to recognise. The three shapes below are that contract - keep them
// stable:
//
//     console::paint(cyan, "  -- Section")     section heading
//     "    Key:  value"                        key/value line
//     "      * item"                           bullet
//
// console::paint() always emits ANSI escapes; the curses layer strips them
// again. That is why painting here is safe in both front-ends.

using report_clock = std::chrono::steady_clock;

// Wall-clock milliseconds since `start`, for the "(12.3 ms)" trailer every
// phase prints through print_duration().
double elapsed_ms(report_clock::time_point start);

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------
// LIEF::to_string(Binary::FORMAT) emits upper-case names ("PE", "ELF",
// "MACHO"), so these comparisons are case-insensitive.
enum class file_format { unknown, pe, elf, macho };

file_format detect_format(const analyzer::file_info_t& info);
const char* format_name(file_format f);

// ---------------------------------------------------------------------------
// Core vocabulary
// ---------------------------------------------------------------------------

void print_banner(const std::string& title);
void print_section(const std::string& text);
void print_kv(const std::string& key, const std::string& value);
void print_kv_colored(const std::string& key,
                      const std::string& value,
                      std::string_view color);
void print_bullet(const std::string& text,
                  std::string_view color = console::grey);
void print_warn(const std::string& text);
void print_duration(double ms);

void print_ip_network_info(const std::string& ip, const cti::network_context& net);

std::string hex_rva(std::uint64_t value);
std::string hex_value(std::uint64_t value);
std::string env_or_empty(const char* name);

// Parses the CTI_BW_KEYS roster: comma-separated "VaultItem=ENV_TARGET"
// entries. A bare "VaultItem" (no '=') is an existence check. Returns false and
// sets `error` on an empty name, a dangling '=', or a duplicate item/target.
bool parse_vault_key_list(const std::string& text,
                          std::vector<secret_store::item_request_t>& out,
                          std::string& error);

// ---------------------------------------------------------------------------
// Per-section report printers
// ---------------------------------------------------------------------------

bool collect_xref_targets(const analyzer::file_info_t& info,
                          bool is_pe, bool is_elf, bool is_macho,
                          std::uint64_t pe_image_base,
                          std::vector<std::uint64_t>& out);

void print_iat_report(const extractor::iat_result_t& r);
void print_got_report(const extractor::got_result_t& r);
void print_xref_asm_report(const r2::xref_asm_result_t& r);
void print_capa_report(const capa::report_t& r);
void print_ml_score_report(const ml_api::score_result_t& r,
                           const std::string& skip_reason);
void print_radare2_report(const r2::bulk_result_t& r);
void print_render_report(const std::string& format,
                         std::size_t rendered_ok,
                         std::size_t rendered_attempted,
                         const std::vector<std::pair<std::string, std::string>>& errors);
void print_pe_overlay_report(const extractor::pe_sections_t& result);
void print_export_report(const extractor::pe_export_table_t& r);
void print_yara_report(const yara_scanner::result_t& r);
// One row of a hexdump, rendered from raw bytes. `data` may be shorter than
// `bytes_per_row` on the final row; the ASCII column is padded so the rows
// stay aligned.
void print_hexdump_row(std::uint64_t address,
                       const std::uint8_t* data,
                       std::size_t count,
                       std::size_t bytes_per_row = 16);
void print_cminer_raw(const std::string& output);
