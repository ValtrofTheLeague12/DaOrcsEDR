#include "app_paths.hpp"

#include <cstdlib>
#include <string>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace app_paths {
namespace {

// The application basename. Every generated path is named after the project, so
// a directory listing of AppData says what it belongs to without needing this
// file open.
constexpr const char* kAppName = "IAProject";

std::filesystem::path resolve_root() {
  // An explicit override wins, and is the hook the tests use.
  if (const char* override_dir = std::getenv("IA_APPDATA_DIR");
      override_dir != nullptr && *override_dir != '\0') {
    return std::filesystem::path(override_dir);
  }

#if defined(_WIN32)
  // Roaming, not Local: these are the user's own settings and state and should
  // follow the account between machines, the same as the panel cache and the
  // sealed credentials already do. LocalAppData is for machine-local caches
  // that a user is happy to lose - a crash dump is, but it shares a root with
  // settings that are not, so roaming keeps the whole tree in one place.
  if (const char* appdata = std::getenv("APPDATA");
      appdata != nullptr && *appdata != '\0') {
    return std::filesystem::path(appdata) / kAppName;
  }
  if (const char* profile = std::getenv("USERPROFILE");
      profile != nullptr && *profile != '\0') {
    return std::filesystem::path(profile) / "AppData" / "Roaming" / kAppName;
  }
  return std::filesystem::path(kAppName);

#else
  // XDG, with the documented fallback.
  if (const char* xdg = std::getenv("XDG_DATA_HOME");
      xdg != nullptr && *xdg != '\0') {
    return std::filesystem::path(xdg) / kAppName;
  }
  if (const char* home = std::getenv("HOME");
      home != nullptr && *home != '\0') {
    return std::filesystem::path(home) / ".local" / "share" / kAppName;
  }
  return std::filesystem::path(kAppName);
#endif
}

}  // namespace

const std::filesystem::path& data_root() {
  // Function-local static: created on first use, and - unlike a namespace-scope
  // constant - not before main(), which matters because an object constructed
  // during static initialisation runs before the working directory is the one
  // the user launched from.
  static const std::filesystem::path root = ensure(resolve_root());
  return root;
}

std::filesystem::path logs_root() {
  return data_root() / "logs";
}

std::filesystem::path cache_root() {
  return data_root() / "cache";
}

std::filesystem::path ensure(const std::filesystem::path& dir) {
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  // ec is deliberately ignored. The caller is about to open a file under `dir`,
  // and that failure reports the full path, which is more use than anything
  // this could say here.
  return dir;
}

}  // namespace app_paths