#include "extractor.hpp"
#include "file_analyzer.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

namespace {

namespace fs = std::filesystem;

int fail(const std::string& message) {
  std::cerr << "[-] FAIL: " << message << '\n';
  return EXIT_FAILURE;
}

}  

int main(int argc, char** argv) {
  fs::path target;
  if (argc > 1) {
    target = argv[1];
  } else {
    target = fs::path(argv[0]).parent_path() / "test_smoke.exe";
  }

  std::cout << "[*] Sample target: " << target.string() << '\n';
  if (!fs::exists(target)) {
    return fail("sample target not found: " + target.string());
  }

  const analyzer::file_info_t info = analyzer::get_file_info(target.string());
  if (analyzer::has_errors(info)) {
    for (const std::string& message : analyzer::get_error_messages(info)) {
      std::cerr << "    " << message << '\n';
    }
    return fail("file analysis of the sample target failed");
  }

  extractor::debug_symbols_t result{};
  if (!extractor::extract_debug_symbols(result, info)) {
    for (const std::string& message : extractor::get_error_messages(result)) {
      std::cerr << "    " << message << '\n';
    }
    return fail("extract_debug_symbols reported an error");
  }

  std::cout << "[*] format=" << result.format
            << " symbols=" << result.symbols.size()
            << " debug-sections=" << result.debug_sections.size()
            << " stripped=" << (result.stripped ? "yes" : "no") << '\n';

  if (!result.has_debug_symbols) {
    return fail("no debug symbols were recovered");
  }

  std::size_t sample_symbols = 0;
  for (const extractor::debug_symbol_t& symbol : result.symbols) {
    if (symbol.name.find("sample_") == std::string::npos) {
      continue;
    }
    ++sample_symbols;
    std::cout << "    [symbol] " << symbol.name << " addr=0x" << std::hex
              << symbol.address << std::dec << '\n';
  }
  if (sample_symbols == 0) {
    return fail("no 'sample_*' function symbols were recovered");
  }

  std::cout << "[+] PASS: " << sample_symbols
            << " sample function symbol(s) recovered from the debug symbol table\n";
  return EXIT_SUCCESS;
}
