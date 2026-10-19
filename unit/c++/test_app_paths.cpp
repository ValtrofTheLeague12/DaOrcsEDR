// test_app_paths.cpp
//
// Unit tests for the AppData root resolver.
//
// This is the rule the whole project depends on: generated files live under
// one root keyed on the app basename, and the same rule is implemented three
// times (here, python/panel/config.py, admin-terminal/core.py) precisely so
// the three cannot drift. Nothing tested that claim before, which is how the
// resolver could be changed here and quietly stop matching the Python one.
//
// It is also the cheapest thing in the codebase to get wrong in a way nobody
// notices: a root that resolves one directory too high writes outside the
// intended tree, and the only symptom is that files turn up somewhere odd.
//
// What these tests CANNOT check is the IA_APPDATA_DIR override: the resolver
// caches into a function-local static on first use, so an in-process test
// cannot observe the effect of changing the environment afterwards, and
// asserting "something non-empty came back" would be a test that cannot fail.
// That belongs in a subprocess test under tests/.

#include "app_paths.hpp"
#include "test_main.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace {

// True when `name` appears as a whole path component.
//
// A component test rather than a suffix test, and that distinction is the whole
// point: logs_root() is "...\IAProject\logs", so a suffix check against
// "IAProject" is wrong for a reason that has nothing to do with the resolver -
// and that mistake shipped here first, as a failing test that looked like a
// product bug.
bool has_component(const fs::path& p, const std::string& name) {
  for (const auto& part : p) {
    if (part.generic_string() == name) return true;
  }
  return false;
}

fs::path scratch(const char* name) {
  const fs::path base = fs::temp_directory_path() / name;
  fs::remove_all(base);
  return base;
}

}  // namespace

TEST(the_harness_itself_runs) {
  // First on purpose. If this one dies, the problem is the harness or the build
  // rather than app_paths, and knowing which half is broken is the difference
  // between a two-minute bisect and an afternoon.
  CHECK(true);
  CHECK_EQ(std::string("ab"), std::string("ab"));
}

TEST(root_is_keyed_on_the_app_basename) {
  const fs::path r = app_paths::data_root();
  CHECK(!r.empty());
  CHECK(has_component(r, "IAProject"));
}

TEST(root_is_absolute) {
  // A relative root would resolve against the current working directory, so the
  // same binary would write to different places depending on where it was
  // launched from - the exact failure the migration existed to remove.
  CHECK(app_paths::data_root().is_absolute());
}

TEST(logs_and_cache_share_one_root) {
  // Same parent, deliberately: the migration's promise is "everything generated
  // lives under one root", and two roots would quietly break it.
  CHECK_EQ(fs::path(app_paths::logs_root()).parent_path().string(),
           fs::path(app_paths::cache_root()).parent_path().string());
}

TEST(logs_and_cache_are_distinct_directories) {
  CHECK(fs::path(app_paths::logs_root()) != fs::path(app_paths::cache_root()));
}

TEST(logs_and_cache_sit_under_the_root) {
  CHECK(has_component(app_paths::logs_root(), "IAProject"));
  CHECK(has_component(app_paths::cache_root(), "IAProject"));
}

TEST(ensure_creates_missing_directories) {
  const fs::path base = scratch("ia_unit_ensure_probe");
  const fs::path made = app_paths::ensure(base / "nested" / "deeper");
  CHECK(fs::is_directory(made));
  fs::remove_all(base);
}

TEST(ensure_is_idempotent) {
  // ensure() runs from a static initialiser, so calling it against a directory
  // that already exists - and is in use - has to be a no-op, not an error.
  const fs::path base = scratch("ia_unit_ensure_idem");
  const fs::path first = app_paths::ensure(base / "sub");
  const fs::path second = app_paths::ensure(first);
  CHECK_EQ(second.string(), first.string());
  CHECK(fs::is_directory(second));
  fs::remove_all(base);
}

TEST(ensure_handles_a_path_with_spaces) {
  // The AppData root routinely contains one ("C:\Users\First Last\AppData"). A
  // resolver that quoted badly would fail only on such machines, which is the
  // worst way for a path bug to present.
  const fs::path base = scratch("ia unit spaces probe");
  const fs::path made = app_paths::ensure(base / "sub dir" / "deeper");
  CHECK(fs::is_directory(made));
  CHECK(made.generic_string().find(' ') != std::string::npos);
  fs::remove_all(base);
}

TEST(the_root_is_stable_across_calls) {
  // Computed once into a function-local static. If that ever recomputed, two
  // phases of one run could disagree about where state lives.
  CHECK_EQ(app_paths::data_root().string(), app_paths::data_root().string());
  CHECK_EQ(app_paths::logs_root().string(), app_paths::logs_root().string());
  CHECK_EQ(app_paths::cache_root().string(), app_paths::cache_root().string());
}

UT_MAIN("app_paths")