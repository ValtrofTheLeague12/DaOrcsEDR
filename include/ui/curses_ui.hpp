#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace curses_ui {

// The startup logo - daorcs.logo when non-empty, otherwise pdcursor.logo, with
// the width of the widest line for centring. Both front-ends draw it at that
// size and never rescale it, so this carries no terminal of its own.
struct logo_t {
  std::vector<std::string> lines;
  int width = 0;
};

// Reads the logo file once. Empty lines when it is missing or unreadable, which
// callers treat as "draw nothing". STATIC_ANALYZER_LOGO overrides the path.
logo_t load_logo();

// Startup banner for runs where the PDCurses session is inactive: the same
// logo, red and centred in the console window. Does nothing when stdout is not
// a terminal, so a redirected run does not get the art in its captured output.
// STATIC_ANALYZER_FORCE_LOGO=1 overrides that, which is how the admin panel's
// captured Build output and pipeline logs show daorcs.logo.
void print_logo_banner();

// Interactive PDCurses front-end. It remains a no-op when stdout is redirected
// or STATIC_ANALYZER_CURSES=0. begin() captures ordinary std::cout output while
// a live progress screen is shown. finish() restores stdout and opens a
// section browser for the completed report.
class session {
 public:
  session();
  ~session();

  session(const session&) = delete;
  session& operator=(const session&) = delete;
  session(session&&) noexcept;
  session& operator=(session&&) noexcept;

  bool begin(const std::string& input, std::size_t total_phases);
  void phase(std::size_t current, const std::string& label);
  // The applicable phase count is only known once the file format has been
  // detected, which happens after begin(). Lets the progress bar re-scale.
  void set_total(std::size_t total_phases);
  void set_dashboard_path(const std::string& path);
  void complete(bool success);
  void shutdown();

  [[nodiscard]] bool active() const noexcept;

 private:
  struct impl;
  std::unique_ptr<impl> impl_;
};

}  // namespace curses_ui
