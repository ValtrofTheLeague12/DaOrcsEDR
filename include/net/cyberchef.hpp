#pragma once

// Client for a locally running CyberChef-server (the podman container).
//
// The encoded-string scan feeds candidate strings to the server and flags
// the ones whose *decoded* form hides suspicious content. Coverage:
//
//   * ROT13 / ROT47 / printable ROT (any amount) / single-byte XOR
//     (keys 1..255) / per-byte bit rotations -> decoded locally to screen,
//     then every suspect is re-decoded through POST /bake so the flag
//     carries the server's own result. Screening locally and confirming
//     over HTTP keeps the request count proportional to findings instead
//     of to the number of strings in the binary - that is what makes this
//     cheap enough to run on every analysis. Printable ROT has no
//     CyberChef op, so that family is decided locally; the same goes for
//     the API-hash table below (a hash is not decodable server-side).
//   * base64 (standard / URL-safe / -enc UTF-16LE), hex, %-encoding,
//     base32, base58, base85 -> POST /magic, CyberChef's automatic
//     encoding detection (it does not know ROT13 - verified - so the two
//     paths are deliberately separate). Strings /magic leaves undecoded
//     get a base64 NUL-check fallback with an explicit
//     "From Base64 + Decode text (UTF-16LE)" confirmation.
//   * API-hash constants: PJW / DJB2 / FNV-1a of common Windows API
//     names, matched against 0x-prefixed and decimal literals in the
//     strings. Pure local math - nothing to bake.
//
// The flagging decision (indicator match on the decoded text) stays on this
// side - see k_indicators in cyberchef.cpp - so a benign sentence that
// happens to decode remains unflagged. Each string yields at most one flag.
// Everything is best-effort: if the server is down the scan returns
// server_ok = false and the analysis continues. Nothing in the analyzer
// starts the container; that remains podman::runner / a manual
// `podman run`.

#include <cstddef>
#include <string>
#include <vector>

#include "ioc_extractor.hpp"  // ioc::encoded_flag_t

namespace cyberchef {

struct options {
  // Loopback first: WSL relays listeners that exist at distro boot, so a
  // container started later may never appear on the Windows loopback. When
  // that happens and CYBERCHEF_URL is unset, the scan falls back to the
  // WSL eth0 address (`wsl -- hostname -I`) - which is why manual runs
  // should publish on all WSL interfaces (`-p 60001:3000`); WSL2's NAT
  // keeps that host-local anyway. CYBERCHEF_URL, when set, disables the
  // fallback and is the only base tried.
  std::string base_url = "http://127.0.0.1:60001";

  long connect_timeout_ms = 800;
  long request_timeout_ms = 5000;

  // Candidate caps: bound the scan even on pathological inputs.
  std::size_t max_rot_candidates    = 100;  // ROT13/47/printable, via /bake
  std::size_t max_xor_candidates    = 100;  // winning XOR keys, via /bake
  std::size_t max_rotate_candidates = 60;   // bit rotations, via /bake
  std::size_t max_magic_candidates  = 60;   // sent to /magic
  // CPU bound for the brute-force screens (xor 255 keys, printable ROT 94
  // amounts, bit rotations 4 x 7): only this many strings are screened.
  std::size_t max_local_screen_strings = 4000;

  std::size_t min_string_length = 8;
  std::size_t max_string_length = 2048;    // longer strings are not candidates
};

struct scan_result_t {
  bool        server_ok = false;  // /health answered inside the timeout
  bool        skipped   = false;  // CYBERCHEF_DISABLE is set
  std::string error;              // why server_ok is false ("" when healthy)

  std::size_t candidates_rot    = 0;  // ROT13/47 + printable-ROT candidates
  std::size_t candidates_xor    = 0;  // winning single-byte XOR keys
  std::size_t candidates_rotate = 0;  // bit-rotation candidates
  std::size_t candidates_hash   = 0;  // API-hash constants recognised
  std::size_t candidates_magic  = 0;
  std::size_t calls            = 0;  // HTTP requests actually made
  std::size_t flags            = 0;  // == flagged.size() when finished

  std::vector<ioc::encoded_flag_t> flagged;
};

// Never throws; safe to call with the server stopped.
scan_result_t scan(const std::vector<std::string>& strings,
                   const options& opts = {});

}  // namespace cyberchef
