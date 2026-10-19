#pragma once

#include <string>
#include <string_view>

// Identity, baked in at compile time.
//
// The point is that the executable describes ITSELF, wherever it ends up. A
// binary on somebody else's disk, in a bundle, or attached to a bug report can
// be asked what it is; nothing has to be shipped alongside it and nothing has
// to be true. Without this, "which commit is this?" is answered by whoever
// remembers which machine they built on.
//
// The values come from CMake, which resolves git once at configure time. A
// non-git build gets the empty string and says so rather than claiming a commit
// it cannot know.
namespace build_info {

// "1.0.0+bd93684.dirty" - the short form printed by --version.
std::string version();

// The full commit hash, or "" when this was not built from a checkout.
std::string commit();

// Branch name, or "".
std::string branch();

// True when the tree had uncommitted changes at configure time. Worth recording
// separately: a binary built from a dirty tree is not reproducible from its
// commit, and saying so is the difference between a useful provenance line and
// a misleading one.
bool dirty();

// "1.0.0+bd93684.dirty (master, build-ucrt)" - the long form.
std::string describe(std::string_view build_dir);

// The directory this build was configured in, from CMake. Used by --version so
// it can name the build tree the binary belongs to.
std::string_view build_dir();

}  // namespace build_info