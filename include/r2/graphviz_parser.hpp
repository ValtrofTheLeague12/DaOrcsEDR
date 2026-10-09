// graphviz_parser.hpp
//
// Parses the Graphviz .dot files produced by r2 ("agfd" / "agCd") using
// libgraphviz (cgraph), and writes a normalized JSON form next to them.
//
// Why this exists: the dashboard previously parsed .dot with regexes
// (python/_create_dashboard.py). That silently mis-parsed real r2 output -
// it undercounted edges on every file tested and could not tell a node
// statement from an edge attribute block. cgraph is the reference parser and
// handles quoted ids, "->" inside label strings, escapes, and comments
// correctly.
//
// Threading: cgraph's parser is not reentrant, so every entry point below
// takes a process-wide lock. The analyzers already run phases
// concurrently, so this is load-bearing, not defensive.
//
// If the project is configured without cgraph (STATIC_ANALYZER_USE_GRAPHVIZ=OFF)
// this header still compiles and every function reports "unavailable" rather
// than failing to build, so the analyzer keeps working with the dashboard's
// regex fallback.

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace graphviz {

using json = nlohmann::json;

// One node of a parsed .dot graph.
struct node_t {
  std::string id;      // node id as it appears in the .dot source
  std::string label;   // `label` attribute, or id when absent
  std::string url;     // `URL` attribute (r2 puts "name/addr" here)
};

// One directed edge. `key` disambiguates multi-edges between the same pair
// of nodes, which occur in CFGs.
struct edge_t {
  std::string from;
  std::string to;
  std::string key;   // "" when the statement was anonymous
};

// A parsed .dot graph.
struct graph_t {
  std::string          name;              // digraph name, e.g. "code" / "section__text"
  std::vector<node_t>  nodes;
  std::vector<edge_t>  edges;

  // Shape metrics, handy for reporting and for the dashboard header.
  std::size_t self_loops = 0;
  std::size_t multi_edges = 0;

  // Serialize to the shape python/_create_dashboard.py already consumes:
  //   {"nodes": [{"id": ..., "label": ...}], "edges": [[from, to], ...]}
  json to_json() const;
};

struct parse_result_t {
  bool        ok = false;
  std::string error;                 // empty when ok
  graph_t     graph;
};

// True when the binary was built with cgraph support. When false every parse
// call returns ok=false with a "built without libgraphviz" error.
bool available();

// Parse .dot source text. Never throws; failures come back in parse_result_t.
parse_result_t parse_text(const std::string& dot_source);

// Read and parse a .dot file from disk. Missing/unreadable files are reported
// through parse_result_t rather than by throwing.
parse_result_t parse_file(const std::string& path);

// Drop leading non-DOT noise (launcher diagnostics, r2 warnings) so the text
// starts at the graph header. Mirrors the behavior the r2 runner already
// applies before writing .dot files; kept here so this module is usable on
// files produced elsewhere.
std::string strip_preamble(const std::string& text);

// Convert a whole directory of *.dot files into a single JSON object keyed by
// graph name, written to `out_json_path` atomically. Missing directory or
// unwritable destination is reported through the return value; per-file
// failures are recorded in the output under "errors" without aborting, so one
// bad graph cannot suppress the rest.
struct dir_result_t {
  bool        ok = false;
  std::string error;
  std::size_t files_seen = 0;
  std::size_t files_parsed = 0;
  std::size_t files_failed = 0;
  std::string written_path;
};

// Convert exactly the listed *.dot files into a single JSON object keyed by
// file stem, written to `out_json_path` atomically. Prefer this over
// convert_directory whenever the caller knows which files belong to the sample
// being analyzed: convert_directory globs a whole directory, so any other
// sample's graphs sitting next to them would fold into this sample's output.
dir_result_t convert_files(const std::vector<std::string>& dot_paths,
                           const std::string& out_json_path);

// Convert every *.dot file in `dot_dir`. Same JSON shape and error handling as
// convert_files(); meant for standalone use (the dot2json tool) on a directory
// that holds a single sample's graphs.
dir_result_t convert_directory(const std::string& dot_dir,
                               const std::string& out_json_path);

// ---------------------------------------------------------------------------
// Tool entry point
// ---------------------------------------------------------------------------
//
// Usage: dot2json <dot_dir> <out_json>
// Kept in the same translation unit so the parser can be exercised without
// running the full analyzer, which is what makes it testable at all.

}  // namespace graphviz
