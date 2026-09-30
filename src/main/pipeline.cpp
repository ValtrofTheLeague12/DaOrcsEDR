#include "pipeline.hpp"

#include <iostream>
#include <sstream>

#include "console.hpp"

namespace pipeline {

// Numbers and prints the next stage that applies. A stage that does not apply
// advances nothing and prints nothing, so the "[phase n/total]" headers only
// ever advertise work that really happens. The PDCurses results browser turns
// each of these headers into its own section.
void phase(context& ctx, bool applies, const std::string& label) {
  if (!applies) return;

  ++ctx.phase_no;
  if (ctx.curses != nullptr) {
    ctx.curses->phase(static_cast<std::size_t>(ctx.phase_no), label);
  }

  std::ostringstream os;
  os << "[phase " << ctx.phase_no << "/" << ctx.total_phases << "] " << label;
  std::cout << '\n' << console::paint(console::yellow, os.str()) << '\n';
}

}  // namespace pipeline
