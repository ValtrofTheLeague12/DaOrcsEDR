#pragma once

// Ctrl+C handling, phase checkpoints, and resuming from one.
//
// A full run is 27 phases over tools that shell out to radare2, capa and a
// network-backed CTI pass, so it is long enough that interrupting it is a
// normal thing to do rather than an accident. Today Ctrl+C kills the process
// wherever it happens: whatever was mid-phase is lost, and there is no record
// anywhere of how far the run actually got.
//
// This module makes the interruption recoverable from both sides.
//
//   * A checkpoint is written after every completed phase, to
//     logs/resume/<stem>.json. Once per phase is a few hundred bytes and costs
//     nothing next to what a phase does, and it means the file is correct even
//     when the process dies the ungraceful way - a crash, a power cut, a kill
//     from Task Manager. A checkpoint written only from the signal handler would
//     be correct only for the polite case.
//
//   * Ctrl+C sets a flag rather than exiting. The run loop checks it between
//     phases and stops cleanly, so run_summary.json is still written and says
//     why. A second Ctrl+C restores the default handler, because a user who
//     presses it twice means it.
//
//   * `--resume` picks up from the checkpoint: phases already in `completed`
//     are skipped. `--from <phase>` is the explicit version, for when the
//     checkpoint is not the one you want.
//
// The skip is a *restart from a point*, not a rehydration: results are held in
// `context`, not re-read from the artifacts on disk, so a skipped phase does
// not leave its output in memory for the phases after it. That is a property of
// the phases, not of this file, so the planner warns about it - by name, from
// the catalog's own dependency list - rather than pretending the resume is free.

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace resume {

// Install the Ctrl+C handler. Idempotent; safe to call before or after the
// crash handlers, and it never touches those.
void install();

// When true, an interrupt does not stop the run.
//
// The default is the opposite and is the right default: Ctrl+C means "stop",
// and a run that ignored it would be a run nobody could end. With this on, the
// FIRST interrupt is consumed by the run loop, which re-runs the phase it
// landed on and carries on with the plan; only a SECOND interrupt stops it, at
// the usual next-phase boundary.
//
// Re-running rather than skipping forward is the point. A phase that was
// interrupted may have left partial output behind - a half-written JSON, a
// truncated artifact - and running the next phase over that is how a report
// ends up quietly wrong. Starting the interrupted phase again produces a clean
// result, and costs one phase of work.
//
// One rewind per run, not one per interrupt. Without that, a second Ctrl+C
// would rewind again and walk the pipeline backwards to the start.
void set_continue_on_interrupt(bool enabled);
bool continues_on_interrupt();

// Where checkpoints live; the same root crash::install() gets. Set once from
// main, because the checkpoint path is derived from a stem the planner only
// learns after the prologue has hashed the sample.
void set_logs_root(const std::filesystem::path& logs_root);

// Start tracking a run. Called by the planner once the stem is known, i.e.
// after the prologue - not from main, which cannot know the stem yet.
void begin(std::string_view pipeline, std::string_view source,
           std::string_view input, std::string_view run_id, std::string_view stem);

// Called by the planner after each phase returns. Writes the checkpoint.
void phase_completed(std::string_view name);

// True once Ctrl+C has been seen. The run loop polls this between phases.
bool stop_requested();

// How many interrupts have arrived. 2 or more means the user gave up on the
// graceful stop.
int interrupts();

// Forget the interrupts recorded so far.
//
// Only for the continue-on-interrupt rewind: the run loop consumes one
// interrupt by re-running the phase it landed on, and must not see the same
// count again at the next boundary or it would rewind on every remaining
// phase. Clearing rather than decrementing keeps it a single call.
void clear_interrupt();

// Drop the checkpoint: a run that finished has nothing to resume, and leaving
// the file behind would invite a pointless second run.
void clear();

// What a checkpoint holds. `completed` is in plan order.
struct point {
  std::string pipeline;
  std::string source;
  std::string input;
  std::string stem;
  std::string run_id;
  std::vector<std::string> completed;
  long long saved_at = 0;
  bool valid = false;
};

// Where the checkpoint for a sample lives.
std::filesystem::path path_for(std::string_view stem,
                               const std::filesystem::path& logs_root);

// Read a checkpoint. A missing or unreadable file is not an error here - it
// returns an invalid point and the caller decides what that means.
point load(const std::filesystem::path& file);

// The checkpoint of the run in progress, for a crash report to print.
std::string describe();

}  // namespace resume