// graphviz_parser.cpp

#include "graphviz_parser.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <system_error>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#ifdef STATIC_ANALYZER_USE_GRAPHVIZ
#include <graphviz/cgraph.h>
#endif

namespace graphviz {

namespace fs = std::filesystem;

#ifdef STATIC_ANALYZER_USE_GRAPHVIZ
namespace {

// cgraph's parser uses process-global state (the default Agdisc and its error
// handler), so concurrent parses would corrupt each other. The analyzer runs
// analysis phases on separate threads, hence the lock.
std::mutex& parse_mutex() {
  static std::mutex m;
  return m;
}

// r2 labels carry DOT escapes: "\l" is a left-justified line break, "\n" a
// centered one, "\r" a right-justified one, and "|" separates columns. The
// dashboard wants a single flat line, so every one of them becomes a space.
std::string flatten_label(const char* raw) {
  if (!raw) return {};
  std::string out;
  out.reserve(std::strlen(raw));
  for (const char* p = raw; *p; ++p) {
    if (*p == '\\' && p[1]) {
      const char n = p[1];
      if (n == 'l' || n == 'n' || n == 'r' || n == 'L' || n == 'N' || n == '|') {
        out.push_back(' ');
        ++p;
        continue;
      }
      if (n == '"' || n == '\\') {
        out.push_back(n);
        ++p;
        continue;
      }
    }
    out.push_back(*p);
  }
  // Collapse the runs of spaces the escapes leave behind, then trim.
  std::string collapsed;
  collapsed.reserve(out.size());
  bool prev_space = false;
  for (char c : out) {
    const bool sp = (c == ' ' || c == '\t' || c == '\r' || c == '\n');
    if (sp) {
      if (!prev_space) collapsed.push_back(' ');
    } else {
      collapsed.push_back(c);
    }
    prev_space = sp;
  }
  const auto b = collapsed.find_first_not_of(' ');
  if (b == std::string::npos) return {};
  const auto e = collapsed.find_last_not_of(' ');
  return collapsed.substr(b, e - b + 1);
}

// cgraph's accessors predate const correctness and take `char*` names, so the
// const_cast here is for the API's benefit only; the literals are not modified.
std::string attr_or_empty(void* obj, const char* name) {
  char* v = agget(obj, const_cast<char*>(name));
  return v ? std::string(v) : std::string();
}

// Count out-edges that share (from,to) with an earlier one. cgraph models a
// multi-edge as separate edges distinguished by a key, and CFGs legitimately
// contain them, so this is counted and reported rather than deduped.
std::size_t count_multi_edges(const graph_t& g) {
  std::map<std::pair<std::string, std::string>, std::size_t> seen;
  std::size_t multi = 0;
  for (const auto& e : g.edges) {
    auto& c = seen[{e.from, e.to}];
    if (c > 0) ++multi;
    ++c;
  }
  return multi;
}

}  // namespace
#endif  // STATIC_ANALYZER_USE_GRAPHVIZ

// ---------------------------------------------------------------------------
// Availability
// ---------------------------------------------------------------------------

bool available() {
#ifdef STATIC_ANALYZER_USE_GRAPHVIZ
  return true;
#else
  return false;
#endif
}

std::string strip_preamble(const std::string& text) {
  const std::size_t pos = text.find("digraph");
  if (pos == std::string::npos) return text;
  // Back up to the start of the line holding "digraph" so a leading
  // "strict " stays attached to the header.
  std::size_t start = 0;
  for (std::size_t i = pos; i-- > 0;) {
    if (text[i] == '\n') {
      start = i + 1;
      break;
    }
  }
  return text.substr(start);
}

// ---------------------------------------------------------------------------
// JSON shape
// ---------------------------------------------------------------------------

json graph_t::to_json() const {
  json nodes_out = json::array();
  for (const auto& n : nodes) {
    json j;
    j["id"] = n.id;
    j["label"] = n.label;
    // `url` is additive: the dashboard's node schema only reads id/label, and
    // an extra key is ignored there.
    if (!n.url.empty()) j["url"] = n.url;
    nodes_out.push_back(std::move(j));
  }
  json edges_out = json::array();
  for (const auto& e : edges) {
    edges_out.push_back(json::array({e.from, e.to}));
  }
  json out;
  out["name"] = name;
  out["nodes"] = std::move(nodes_out);
  out["edges"] = std::move(edges_out);
  out["self_loops"] = self_loops;
  out["multi_edges"] = multi_edges;
  return out;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

parse_result_t parse_text(const std::string& dot_source) {
  parse_result_t res;

#ifndef STATIC_ANALYZER_USE_GRAPHVIZ
  res.error = "built without libgraphviz (STATIC_ANALYZER_USE_GRAPHVIZ=OFF)";
  return res;
#else
  const std::string cleaned = strip_preamble(dot_source);
  if (cleaned.find("digraph") == std::string::npos &&
      cleaned.find("graph") == std::string::npos) {
    res.error = "no graph header found in DOT source";
    return res;
  }

  std::lock_guard<std::mutex> lock(parse_mutex());

  // agmemread keeps pointers into the buffer it is handed, so that buffer must
  // outlive the graph. `cleaned` does: it lives to the end of this function and
  // agclose runs before we return.
  Agraph_t* g = agmemread(cleaned.c_str());
  if (!g) {
    res.error = "cgraph could not parse the DOT source";
    return res;
  }

  graph_t out;
  out.name = agnameof(g) ? agnameof(g) : "";

  // Nodes. cgraph has already applied default attribute statements, so a node
  // that appears only as an edge endpoint still shows up with a valid id.
  for (Agnode_t* n = agfstnode(g); n; n = agnxtnode(g, n)) {
    node_t node;
    node.id = agnameof(n) ? agnameof(n) : "";
    const std::string raw_label = attr_or_empty(n, "label");
    node.label = raw_label.empty() ? node.id : flatten_label(raw_label.c_str());
    node.url = attr_or_empty(n, "URL");
    out.nodes.push_back(std::move(node));
  }

  // Edges. agfstout/agnxtout visit each edge exactly once, as the out-edge of
  // its tail. Using agfstedge/agnxtedge instead walks the node's whole edge set
  // (both the in- and out-edge representations) and double-counts every edge -
  // that mistake reported 388 edges for a graph that has 194.
  for (Agnode_t* n = agfstnode(g); n; n = agnxtnode(g, n)) {
    for (Agedge_t* e = agfstout(g, n); e; e = agnxtout(g, e)) {
      edge_t edge;
      const char* from = agnameof(agtail(e));
      const char* to = agnameof(aghead(e));
      edge.from = from ? from : "";
      edge.to = to ? to : "";
      edge.key = agnameof(e) ? agnameof(e) : "";
      if (agtail(e) == aghead(e)) ++out.self_loops;
      out.edges.push_back(std::move(edge));
    }
  }

  agclose(g);

  out.multi_edges = count_multi_edges(out);
  res.graph = std::move(out);
  res.ok = true;
  return res;
#endif
}

parse_result_t parse_file(const std::string& path) {
  parse_result_t res;
  std::error_code ec;
  if (!fs::is_regular_file(path, ec)) {
    res.error = "not a regular file: " + path;
    return res;
  }

  std::ifstream in(path, std::ios::binary);
  if (!in) {
    res.error = "cannot open: " + path;
    return res;
  }
  std::ostringstream buf;
  buf << in.rdbuf();
  if (in.bad()) {
    res.error = "read error: " + path;
    return res;
  }
  return parse_text(buf.str());
}

namespace {

// Atomic write, matching the pattern used elsewhere in the project: a unique
// temp file in the destination directory, then rename. A failed run therefore
// never leaves a half-written graphs.json behind.
bool write_atomic(const fs::path& target, const std::string& content) {
  std::error_code ec;
  if (target.has_parent_path()) {
    fs::create_directories(target.parent_path(), ec);
    if (ec) return false;
  }

  static std::mutex io_mutex;
  std::lock_guard<std::mutex> lock(io_mutex);

  const auto stamp =
      std::chrono::steady_clock::now().time_since_epoch().count();
#ifdef _WIN32
  const auto pid = static_cast<unsigned long>(::_getpid());
#else
  const auto pid = static_cast<unsigned long>(::getpid());
#endif
  fs::path tmp = target;
  tmp += ".tmp." + std::to_string(pid) + "." + std::to_string(stamp);

  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    out.flush();
    if (!out) {
      std::error_code rm;
      fs::remove(tmp, rm);
      return false;
    }
  }

  fs::rename(tmp, target, ec);
  if (ec) {
    // rename() over an existing file can fail on some Windows configurations;
    // drop the old file and retry once.
    std::error_code rm;
    fs::remove(target, rm);
    ec.clear();
    fs::rename(tmp, target, ec);
    if (ec) {
      std::error_code rm2;
      fs::remove(tmp, rm2);
      return false;
    }
  }
  return true;
}

}  // namespace


dir_result_t convert_files(const std::vector<std::string>& dot_paths,
                           const std::string& out_json_path) {
  dir_result_t res;
  if (!available()) {
    res.error = "built without libgraphviz (STATIC_ANALYZER_USE_GRAPHVIZ=OFF)";
    return res;
  }

  // Sort the paths so the output JSON is byte-stable across runs; without this
  // the same inputs would produce differently-ordered keys.
  std::vector<fs::path> dot_files;
  dot_files.reserve(dot_paths.size());
  for (const auto& p : dot_paths) dot_files.emplace_back(p);
  std::sort(dot_files.begin(), dot_files.end());

  json graphs = json::object();
  json errors = json::array();
  for (const auto& path : dot_files) {
    ++res.files_seen;
    const std::string stem = path.stem().string();
    parse_result_t parsed = parse_file(path.string());
    if (!parsed.ok) {
      ++res.files_failed;
      errors.push_back({{"file", stem}, {"error", parsed.error}});
      continue;
    }
    ++res.files_parsed;
    // Key on the FILE STEM, not the digraph name. r2 names every whole-program
    // callgraph "digraph code", and exports/radare2 accumulates artifacts from
    // every sample ever analyzed, so 10 unrelated samples produce 20 files all
    // named "code". Keying on the graph name would collide them and could
    // render one sample's callgraph on another sample's dashboard. The stem is
    // <stem>_callgraph / <stem>_section_<name>, so it is unique per sample.
    // The digraph name is still recorded inside each graph for display.
    graphs[stem] = parsed.graph.to_json();
  }

  json doc;
  doc["graphs"] = std::move(graphs);
  doc["errors"] = std::move(errors);
  doc["parser"] = "libgraphviz-cgraph";
  doc["stats"] = {{"files_seen", res.files_seen},
                  {"files_parsed", res.files_parsed},
                  {"files_failed", res.files_failed}};

  const std::string text = doc.dump(2);
  if (!write_atomic(fs::path(out_json_path), text)) {
    res.error = "cannot write: " + out_json_path;
    return res;
  }
  res.written_path = out_json_path;
  res.ok = true;
  return res;
}

dir_result_t convert_directory(const std::string& dot_dir,
                               const std::string& out_json_path) {
  dir_result_t res;
  if (!available()) {
    res.error = "built without libgraphviz (STATIC_ANALYZER_USE_GRAPHVIZ=OFF)";
    return res;
  }

  std::error_code ec;
  if (!fs::is_directory(dot_dir, ec)) {
    res.error = "not a directory: " + dot_dir;
    return res;
  }

  std::vector<std::string> dot_files;
  for (const auto& entry : fs::directory_iterator(dot_dir, ec)) {
    if (ec) break;
    if (!entry.is_regular_file(ec)) continue;
    if (entry.path().extension() == ".dot")
      dot_files.push_back(entry.path().string());
  }
  return convert_files(dot_files, out_json_path);
}

}  // namespace graphviz

// ---------------------------------------------------------------------------
// Tool entry point
// ---------------------------------------------------------------------------
//
// Usage: dot2json <dot_dir> <out_json>
// Lives in the same translation unit so the parser can be exercised without
// running the whole analyzer, which is what makes it testable at all.

#ifdef GRAPHVIZ_PARSER_STANDALONE
int main(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: dot2json <dot_dir> <out_json>\n");
    return 2;
  }
  if (!graphviz::available()) {
    std::fprintf(stderr, "error: built without libgraphviz support\n");
    return 3;
  }
  const auto res = graphviz::convert_directory(argv[1], argv[2]);
  if (!res.ok) {
    std::fprintf(stderr, "error: %s\n", res.error.c_str());
    return 1;
  }
  std::printf("parsed %zu/%zu .dot file(s) -> %s\n", res.files_parsed,
              res.files_seen, res.written_path.c_str());
  return 0;
}
#endif

