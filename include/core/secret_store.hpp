#pragma once

// secret_store.hpp — reads a single credential from a running `bw serve`.
//
// Design constraints, in priority order:
//   1. Never at rest. Nothing is written to disk; the value is returned by
//      value so it dies with the caller's local variable.
//   2. Never logged. This file deliberately has no LOG_* call, and the value
//      must not be passed to one - logging.cpp performs no redaction, and
//      there are ~260 call sites where the habit is easy to slip into.
//   3. Never serialized. The extraction exporter writes whole structures to
//      exports/*.json, so a key must not become a member of anything that
//      reaches it.
//   4. Narrowest scope. Exactly one named item is fetched. "Fetch the whole
//      vault" is deliberately not supported: it turns one leaked key into the
//      whole vault.
//
// The caller is expected to be opt-in. With CTI_KEY_NAME unset, nothing here
// runs and the analyzer behaves exactly as it did before.

#include <string>

namespace secret_store {

struct result_t {
  bool        ok = false;
  std::string value;
  std::string error;   // operator-facing; never contains secret material
};

// Fetches one vault item's password by exact item name.
//
// base_url must be a loopback address. It is validated rather than trusted:
// bw serve allowlists localhost/127.0.0.1/[::1] and rejects requests carrying
// an Origin header, and an attacker who can set the environment must not be
// able to point the session key at their own host.
//
// Preconditions (the operator runs these; the analyzer never prompts):
//     bw login
//     export BW_SESSION=$(bw unlock --raw)
//     bw sync
//     bw serve                       # binds localhost:8087 by default
result_t fetch_from_bw_serve(const std::string& item_name,
                             const std::string& base_url = "http://127.0.0.1:8087");

}  // namespace secret_store
