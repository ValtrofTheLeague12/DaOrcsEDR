#include "console.hpp"

#include "logging.hpp"

#include <cstdio>
#include <iomanip>
#include <iostream>
#include <sstream>

#ifdef _WIN32
  #include <windows.h>
#endif

namespace console {

std::string paint(std::string_view color, std::string_view message) {
  std::string out;
  out.reserve(color.size() + message.size() + reset.size());
  out += color;
  out += message;
  out += reset;
  return out;
}

void success(std::string_view message) {
  LOG_INFO("{}", message);
  std::cout << paint(green, "[+] ") << message << '\n';
}

void error(std::string_view message) {
  LOG_ERROR("{}", message);
  std::cout << paint(red, "[-] ") << message << '\n';
}

void info(std::string_view message) {
  LOG_DEBUG("{}", message);
  std::cout << paint(cyan, "[*] ") << message << '\n';
}

void enable_utf8_output() {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
  const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode = 0;
  if (output != nullptr && output != INVALID_HANDLE_VALUE &&
      GetConsoleMode(output, &mode)) {
    SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  }
#endif
}


void print_magic_header(const analyzer::file_info_t& info) {
  if (info.header_signature.empty()) return;
  std::cout << "    " << paint(grey, info.header_signature) << '\n';
}

void print_magic_offset(const analyzer::file_info_t& info) {
  if (info.binary_magic.empty()) return;

  // Built with a stream and emitted through std::cout, not std::printf. The
  // curses results browser captures output by swapping std::cout's rdbuf, so
  // anything written with printf bypasses the capture entirely and leaks to the
  // real terminal, out of order with the rest of the report.
  std::ostringstream line;
  line << "    Header bytes (" << info.binary_magic.size() << "): ";
  for (std::size_t i = 0; i < info.binary_magic.size(); ++i) {
    line << std::hex << std::setw(2) << std::setfill('0')
         << static_cast<unsigned>(info.binary_magic[i]) << ' ';
  }
  std::cout << line.str() << '\n';
}

void print_available_fields(const analyzer::file_info_t& file_info) {
  std::cout << paint(yellow, "    Available fields:") << '\n';

  auto line = [](const char* name, const std::string& value) {
    if (value.empty()) return;
    std::cout << "        " << name << ": " << value << '\n';
  };

  line("filepath",    file_info.filepath);
  line("filename",    file_info.filename);
  line("extension",   file_info.extension);
  line("file_magic",  file_info.file_magic);
  line("size",        std::to_string(file_info.size));
  line("executable",  file_info.type.is_executable ? "yes" : "no");
  line("format",      file_info.type.executable_type);
}


void print_entropy_and_chi2(double entropy, double chi2) {
  char buf[128];
  std::snprintf(buf, sizeof(buf),
                "      entropy = %.4f  chi2 = %.2f", entropy, chi2);
  std::cout << paint(grey, buf) << '\n';
}


void print_tree_header(std::string_view label) {
  std::cout << paint(yellow, label) << '\n';
}

void print_tree_stage(std::string_view stage,
                      const std::vector<std::string>& messages,
                      bool is_last_stage) {
  const std::string stage_connector = is_last_stage ? "└── " : "├── ";
  const std::string msg_prefix      = is_last_stage ? "    " : "│   ";

  std::cout << paint(cyan, stage_connector)
            << paint(cyan, stage)
            << '\n';

  for (std::size_t j = 0; j < messages.size(); ++j) {
    const bool last_msg = (j + 1 == messages.size());
    const std::string msg_connector = last_msg ? "└── " : "├── ";

    std::cout << paint(cyan, msg_prefix + msg_connector)
              << messages[j] << '\n';
  }
}

void print_tree_stages(const std::vector<extractor::stage_errors_t>& stages) {
  if (stages.empty()) {
    success("Pipeline errors: none");
    return;
  }

  print_tree_header("Pipeline errors");

  for (std::size_t i = 0; i < stages.size(); ++i) {
    const bool last_stage = (i + 1 == stages.size());
    print_tree_stage(stages[i].stage, stages[i].messages, last_stage);
  }
}

}  