#pragma once

// secret_store.hpp — reads named credentials from a running `bw serve`.
//
// Design constraints, in priority order:
//   1. Never at rest. Nothing is written to disk; values are returned by
//      value so they die with the caller's local variable.
//   2. Never logged. This file deliberately has no LOG_* call, and no value
//      must be passed to one - logging.cpp performs no redaction, and there
//      are ~260 call sites where the habit is easy to slip into.
//   3. Never serialized. The extraction exporter writes whole structures to
//      exports/*.json, so a key must not become a member of anything that
//      reaches it.
//   4. Narrowest scope. Only explicitly named items are read; "fetch the
//      whole vault" is deliberately not supported - it turns one leaked key
//      into the whole vault. An item requested without a target is merely
//      checked for existence and its password is never read.
//
// The caller is expected to be opt-in. With CTI_BW_KEYS (and the legacy
// CTI_KEY_NAME) unset, nothing here runs and the analyzer behaves exactly as
// it did before.

#include <string>
#include <vector>

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

// ---------------------------------------------------------------------------
// Batch lookup (the CTI key roster)
// ---------------------------------------------------------------------------

struct item_request_t {
  std::string name;    // exact vault item name
  std::string target;  // environment variable to fill; empty = existence check only
};

enum class item_state {
  missing,     // no vault item carries this exact name
  ambiguous,   // several items share the name; refusing to guess
  unusable,    // item found, but its login.password could not be read
  present,     // item found; `value` is filled when a target was requested
};

const char* to_string(item_state state);

struct item_result_t {
  std::string name;
  std::string target;
  item_state  state        = item_state::missing;
  bool        value_loaded = false;  // login.password was read into `value`
  std::string value;                 // secret; never logged or serialized
  std::string error;                 // operator-facing; never secret material
};

struct batch_result_t {
  bool        listing_ok  = false;   // the vault listing request itself succeeded
  std::size_t vault_items = 0;       // items visible to this session
  std::string error;                 // listing-level failure; empty on success
  std::vector<item_result_t> items;  // one entry per request, in request order
};

// Checks every requested item against a single vault listing and reads the
// password of the ones that both exist and carry a target. Existence-only
// requests (empty target) never touch the secret material. On a listing-level
// failure every request comes back as `unusable` carrying the same error.
batch_result_t fetch_many_from_bw_serve(const std::vector<item_request_t>& requests,
                                        const std::string& base_url = "http://127.0.0.1:8087");

}  // namespace secret_store
