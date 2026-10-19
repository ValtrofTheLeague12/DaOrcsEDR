#pragma once

#include <filesystem>

// Where everything this program GENERATES lives.
//
// The rule: nothing the analyzer produces is written into the source tree.
// Generated files are not source, they are machine state, and the three costs
// of putting them in the repo are that `git status` is permanently noisy, a
// backup or an archive of the tree sweeps up gigabytes of run logs and crash
// dumps, and two checkouts of the same project on one machine overwrite each
// other's state.
//
// Everything therefore hangs off ONE root, named after the application rather
// than after any one feature, so a reader who finds
//
//     %APPDATA%/IAProject
//
// knows they have found everything and not merely the panel's half of it.
// Subdirectories:
//
//     logs          run logs, crash reports + minidumps, debug dumps, resume
//                   checkpoints, trace.txt, YARA rule caches
//     cache         provider and tool caches (cti-cache and friends)
//     panel-cache   the admin panel's own cache
//     bundle-keys   evidence-bundle encryption keys
//     mega-secrets  sealed MEGA credentials
//
// Two things deliberately do NOT move, because they are inputs or deliverables
// rather than machine state:
//
//   exports/   analysis results. These are what the operator browses, opens and
//              hands to someone else; a path under AppData would be an awkward
//              thing to point a colleague at.
//   data/      the reference corpus (known_pe_hashes.jsonl). Checked in.
//
// Set IA_APPDATA_DIR to relocate the whole tree, which is what the tests and
// any "give me a throwaway run" use.
namespace app_paths {

// The single root. Created on first use.
const std::filesystem::path& data_root();

// <root>/logs - run logs, dumps, resume checkpoints, trace, YARA caches.
std::filesystem::path logs_root();

// <root>/cache - regenerable provider/tool caches.
std::filesystem::path cache_root();

// Create `dir` and return it, ignoring failure. Every writer wants the
// directory to exist and none of them can do anything useful if it does not,
// so the failure is left to surface at the point of use with a real path in the
// error message rather than here with none.
std::filesystem::path ensure(const std::filesystem::path& dir);

}  // namespace app_paths