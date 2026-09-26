#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "file_analyzer.hpp"
#include "extractor.hpp"

namespace console {

inline constexpr std::string_view white = "\x1b[37m"; 
inline constexpr std::string_view reset  = "\x1b[0m";
inline constexpr std::string_view red    = "\x1b[31m";
inline constexpr std::string_view green  = "\x1b[32m";
inline constexpr std::string_view yellow = "\x1b[33m";
inline constexpr std::string_view cyan   = "\x1b[36m";
inline constexpr std::string_view grey   = "\x1b[90m";

std::string paint(std::string_view color, std::string_view message);
void success(std::string_view message);
void error(std::string_view message);
void info(std::string_view message);
void enable_utf8_output();
void print_magic_header(const analyzer::file_info_t& info);
void print_magic_offset(const analyzer::file_info_t& info);
void print_available_fields(const analyzer::file_info_t& file_info);

void print_entropy_and_chi2(double entropy, double chi2);
void print_tree_header(std::string_view label);
void print_tree_stage(std::string_view stage,
                      const std::vector<std::string>& messages,
                      bool is_last_stage);
void print_tree_stages(const std::vector<extractor::stage_errors_t>& stages);

}  