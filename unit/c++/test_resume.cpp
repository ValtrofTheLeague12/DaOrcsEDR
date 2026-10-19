// test_resume.cpp
//
// Unit tests for the resume checkpoint.
//
// Resume is the feature most likely to be trusted and least likely to be
// checked. A checkpoint that is malformed, or that reports a phase completed
// when it was not, does the worst kind of thing: it fails silently, by skipping
// work the operator believes ran. The reported results then describe a run that
// never happened.
//
// So this covers the round trip and the "which phases are already done" query,
// which is the whole of the logic. The signal handling is not unit-testable -
// it is covered by tests/test_pipeline_cli.py's black-box stop case, and by the
// SA_SELFTEST_INTERRUPT path that was verified during development.

#include "resume.hpp"
#include "test_main.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using resume::point;

namespace {

// Every test writes under a scratch logs root: begin() writes a real file, and
// pointing it at the operator's profile to test it would be the single worst
// thing this suite could do.
fs::path use_scratch_root(const char* name) {
  const fs::path scratch =
      fs::temp_directory_path() / ("ia_unit_resume_" + std::string(name));
  fs::remove_all(scratch);
  resume::set_logs_root(scratch);
  return scratch;
}

point load(const fs::path& logs_root, const std::string& stem) {
  return resume::load(resume::path_for(stem, logs_root));
}

}  // namespace

TEST(begin_alone_writes_no_checkpoint) {
  // begin() only records the run's identity in memory. The file is written by
  // the first phase_completed(), and that is deliberate rather than incidental:
  // a run that dies before completing anything has nothing to resume from, and a
  // checkpoint saying "started" would make --resume skip nothing while looking
  // like it had.
  //
  // This test asserts the behaviour the code has. An earlier draft asserted
  // that begin() alone produces a valid point, and failed - which is the suite
  // earning its keep on the first run.
  const fs::path root = use_scratch_root("beginonly");
  resume::begin("default", "builtin:default", "a.exe", "run-1", "a");
  CHECK(!load(root, "a").valid);

  resume::phase_completed("extraction");
  CHECK(load(root, "a").valid);
}

TEST(completed_phases_round_trip) {
  const fs::path root = use_scratch_root("roundtrip");
  resume::begin("default", "builtin:default", "a.exe", "run-2", "a");
  resume::phase_completed("extraction");
  resume::phase_completed("capa");

  const point p = load(root, "a");
  CHECK(p.valid);
  CHECK_EQ(p.pipeline, std::string("default"));
  CHECK_EQ(p.source, std::string("builtin:default"));
  CHECK_EQ(p.input, std::string("a.exe"));
  CHECK_EQ(p.run_id, std::string("run-2"));
  CHECK_EQ(p.stem, std::string("a"));
  CHECK_EQ(p.completed.size(), std::size_t{2});
  CHECK_EQ(resume::describe().empty(), false);
}

TEST(a_repeated_phase_is_appended_each_time) {
  // The behaviour as implemented, asserted rather than assumed.
  //
  // phase_completed() appends unconditionally, so a phase selected twice by the
  // plan appears twice in `completed`. That is harmless for the one thing the
  // field is used for - building a set of phases to skip - where a repeat
  // collapses. It is recorded here because "in plan order" is the header's
  // description of the field, and a reader would otherwise assume the list is a
  // set and be surprised.
  //
  // If a consumer ever needs a unique, ordered list - counting completed phases
  // for a progress figure, say - this test is where that assumption breaks, and
  // the fix belongs in resume.cpp rather than at the call site.
  const fs::path root = use_scratch_root("dupes");
  resume::begin("default", "builtin:default", "a.exe", "run-3", "a");
  resume::phase_completed("extraction");
  resume::phase_completed("extraction");
  resume::phase_completed("capa");
  CHECK_EQ(load(root, "a").completed.size(), std::size_t{3});
}

TEST(completed_phases_keep_plan_order) {
  const fs::path root = use_scratch_root("order");
  resume::begin("default", "builtin:default", "a.exe", "run-7", "a");
  resume::phase_completed("capa");
  resume::phase_completed("extraction");
  resume::phase_completed("summary");
  const point p = load(root, "a");
  CHECK_EQ(p.completed.size(), std::size_t{3});
  CHECK_EQ(p.completed[0], std::string("capa"));
  CHECK_EQ(p.completed[1], std::string("extraction"));
  CHECK_EQ(p.completed[2], std::string("summary"));
}

TEST(no_checkpoint_means_invalid_not_crash) {
  // The common case on a first run. load() must return an invalid point rather
  // than throwing, or every clean run of the analyzer would need a guard.
  const fs::path root = use_scratch_root("absent");
  const point p = load(root, "never-seen-sample");
  CHECK(!p.valid);
  CHECK(p.completed.empty());
}

TEST(an_empty_file_is_invalid_not_a_crash) {
  // A checkpoint truncated by a kill -9, or a disk that filled mid-write. The
  // operator's next move is --resume, and it must degrade to "start from the
  // top", not to a stack trace.
  const fs::path root = use_scratch_root("truncated");
  const fs::path file = resume::path_for("cut", root);
  fs::create_directories(file.parent_path());
  { std::ofstream out(file); out << "{\"pipeline\": \"def"; }
  const point p = resume::load(file);
  CHECK(!p.valid);
}

TEST(stop_is_not_requested_before_it_is) {
  use_scratch_root("stopflag");
  resume::begin("default", "builtin:default", "a.exe", "run-4", "a");
  CHECK(!resume::stop_requested());
  CHECK_EQ(resume::interrupts(), 0);
}

TEST(clear_removes_the_checkpoint) {
  const fs::path root = use_scratch_root("clear");
  resume::begin("default", "builtin:default", "a.exe", "run-5", "a");
  resume::phase_completed("extraction");
  CHECK(load(root, "a").valid);
  resume::clear();
  // The whole point of clear(): a successful run must not leave a checkpoint
  // behind, or the NEXT run of the same sample would skip its phases.
  CHECK(!load(root, "a").valid);
}

TEST(checkpoints_are_separated_per_sample) {
  // Two samples analysed back to back must not read each other's progress, or
  // the second silently skips whatever the first happened to complete.
  const fs::path root = use_scratch_root("persample");
  resume::begin("default", "builtin:default", "one.exe", "run-6", "one");
  resume::phase_completed("capa");

  const point other = load(root, "two");
  CHECK(!other.valid);
  CHECK(other.completed.empty());

  CHECK(load(root, "one").valid);
  CHECK_EQ(load(root, "one").completed.size(), std::size_t{1});
}

UT_MAIN("resume")