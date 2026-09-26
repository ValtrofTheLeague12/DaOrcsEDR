#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace curses_ui {

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
