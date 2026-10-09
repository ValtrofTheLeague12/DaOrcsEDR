// visualizer.hpp
//
// Generates the interactive HTML threat dashboard. The heavy lifting is done
// by a Python script (python/_create_dashboard.py, rendered from
// python/templates/dashboard.html.j2), launched through proc::run — the same
// subprocess plumbing used for capa / radare2 / the local API server.
//
// The C++ side only:
//   * collects the path of every exported artifact,
//   * invokes the Python generator with those paths,
//   * reports the resulting HTML file (or a human-readable error).

#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace visualizer {

// Inputs for one dashboard build. All paths are relative to the current
// working directory (the process CWD), which is where the analyzer runs.
struct options {
    // Interpreter used to run the generator ("py" on this machine).
    std::string python = "py";
    // Path to the generator script.
    std::string script = "python/_create_dashboard.py";
    // Directory for the generated HTML.
    std::string output_dir = "exports/dashboard";
    // Output basename (usually the artifact stem). Empty = derive from input.
    std::string output_name;

    // Exported artifact paths (empty values are skipped by the generator).
    std::string fileinfo;
    std::string hash;
    std::string ioc;
    std::string extraction;
    std::string capa;
    std::string iat;
    std::string got;
    std::string radare2;
    std::string malapi;
    std::string asm_json;      // enriched per-function assembly JSON
    std::string callgraph_dot; // whole-program call graph .dot
    std::string section_dot;   // per-section CFG .dot
    std::string graphs_json;   // cgraph-normalized graphs.json (optional; when
                               // set the dashboard skips regex-parsing the
                               // .dot files above)
    std::string cti;           // CTI report JSON (per-IOC geo / ASN / verdicts)
    std::string stix;          // STIX 2.1 bundle (ATT&CK techniques, indicators)
    std::string navigator;     // ATT&CK Navigator layer JSON
    std::string ml;            // EMBER2024 model score JSON (exports/<stem>_analysis/ml/...)
    std::string files_root;    // read-only artifact tree embedded in dashboard

    // Hard cap on the total bytes of embedded JSON, so a huge sample cannot
    // produce an unusable (multi-hundred-MB) HTML file.
    std::size_t max_embed_bytes = 24u * 1024u * 1024u;

    // Subprocess budget.
    std::chrono::milliseconds timeout{120000};
    std::size_t max_stdout_bytes = 8u * 1024u * 1024u;
    std::size_t max_stderr_bytes = 1u * 1024u * 1024u;
};

struct result {
    bool ok = false;
    std::string html_path;   // set when ok
    std::string error;       // set when !ok
    std::string command_line;
    std::size_t html_bytes = 0;
    double seconds = 0.0;
    int exit_code = 0;
    std::string stderr_tail;
};

// Renders the dashboard. Never throws; failures land in result::error.
result render(const options& opts);

}  // namespace visualizer