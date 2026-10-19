#include "build_info.hpp"

#ifndef IA_BUILD_VERSION
#define IA_BUILD_VERSION "0.0.0-unknown"
#endif
#ifndef IA_BUILD_COMMIT
#define IA_BUILD_COMMIT ""
#endif
#ifndef IA_BUILD_BRANCH
#define IA_BUILD_BRANCH ""
#endif
#ifndef IA_BUILD_DIRTY
#define IA_BUILD_DIRTY 0
#endif
#ifndef IA_BUILD_DIR
#define IA_BUILD_DIR ""
#endif

namespace build_info {

std::string commit() {
  return IA_BUILD_COMMIT;
}

std::string branch() {
  return IA_BUILD_BRANCH;
}

bool dirty() {
  return IA_BUILD_DIRTY != 0;
}

std::string_view build_dir() {
  return IA_BUILD_DIR;
}

std::string version() {
  std::string out = IA_BUILD_VERSION;
  // No commit means this was not built from a checkout - a tarball, a vendored
  // copy, a build machine with no git. Saying "unknown" is honest; leaving the
  // string bare would read like a version of 0.0.0 that somebody meant.
  if (std::string(IA_BUILD_COMMIT).empty()) return out + "+unknown";
  out += "+";
  out += std::string(IA_BUILD_COMMIT).substr(0, 7);
  if (dirty()) out += ".dirty";
  return out;
}

std::string describe(std::string_view build_dir) {
  std::string out = "static_analyzer ";
  out += version();
  if (!branch().empty()) {
    out += " (";
    out += branch();
    if (!build_dir.empty()) {
      out += ", ";
      out += build_dir;
    }
    out += ")";
  }
  return out;
}

}  // namespace build_info