// visualizer.cpp
//
// Thin wrapper around python/_create_dashboard.py. All the HTML/CSS/JS lives
// in python/templates/dashboard.html.j2; this file only marshals the artifact
// paths into argv and checks the exit status — exactly the same shape as the
// capa / radare2 runners (proc::run, timeout, output caps, process-tree kill).

#include "visualizer.hpp"

#include <chrono>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include "logging.hpp"
#include "process_runner.hpp"

namespace visualizer {

namespace fs = std::filesystem;
using clock_type = std::chrono::steady_clock;

namespace {

void add_opt(std::vector<std::string>& argv,
             const char* flag,
             const std::string& value) {
    if (value.empty()) return;
    argv.push_back(flag);
    argv.push_back(value);
}

std::string tail_of(const std::string& text, std::size_t max_chars) {
    if (text.size() <= max_chars) return text;
    return "..." + text.substr(text.size() - max_chars);
}

std::size_t file_size_or_zero(const std::string& path) {
    std::error_code ec;
    const auto n = fs::file_size(path, ec);
    if (ec) return 0;
    return static_cast<std::size_t>(n);
}

}  // namespace

result render(const options& opts) {
    result res;
    const auto started = clock_type::now();

    if (!fs::is_regular_file(opts.script)) {
        res.error = "dashboard generator not found: '" + opts.script + "'";
        LOG_ERROR("visualizer: {}", res.error);
        return res;
    }

    std::vector<std::string> args;
    args.push_back(opts.script);
    add_opt(args, "--fileinfo",   opts.fileinfo);
    add_opt(args, "--hash",       opts.hash);
    add_opt(args, "--ioc",        opts.ioc);
    add_opt(args, "--extraction", opts.extraction);
    add_opt(args, "--capa",       opts.capa);
    add_opt(args, "--iat",        opts.iat);
    add_opt(args, "--got",        opts.got);
    add_opt(args, "--radare2",    opts.radare2);
    add_opt(args, "--malapi",     opts.malapi);
    add_opt(args, "--cti",        opts.cti);
    add_opt(args, "--stix",       opts.stix);
    add_opt(args, "--navigator",  opts.navigator);
    add_opt(args, "--files-root", opts.files_root);
    add_opt(args, "--asm-json",   opts.asm_json);
    add_opt(args, "--callgraph",  opts.callgraph_dot);
    add_opt(args, "--section-dot",opts.section_dot);
    add_opt(args, "--graphs-json",opts.graphs_json);
    add_opt(args, "--out-dir",    opts.output_dir);
    add_opt(args, "--out-name",   opts.output_name);
    args.push_back("--max-embed-bytes");
    args.push_back(std::to_string(opts.max_embed_bytes));

    {
        std::string line = opts.python;
        for (const auto& a : args) {
            line += ' ';
            if (a.find_first_of(" \t\"") != std::string::npos) line += '"' + a + '"';
            else line += a;
        }
        res.command_line = line;
    }
    LOG_INFO("visualizer: run: {}", res.command_line);

    proc::run_options ro;
    ro.timeout          = opts.timeout;
    ro.max_stdout_bytes = opts.max_stdout_bytes;
    ro.max_stderr_bytes = opts.max_stderr_bytes;

    const proc::run_result r = proc::run(opts.python, args, ro);
    res.exit_code   = r.exit_code;
    res.seconds     = std::chrono::duration<double>(clock_type::now() - started).count();
    res.stderr_tail = tail_of(r.std_err, 4096);

    if (r.status != proc::launch_status::ok) {
        res.error = std::string("dashboard generator ") + proc::to_string(r.status) +
                    (r.error.empty() ? "" : ": " + r.error);
        LOG_ERROR("visualizer: {}", res.error);
        return res;
    }

    if (r.exit_code != 0) {
        res.error = "dashboard generator exited with code " +
                    std::to_string(r.exit_code) +
                    (res.stderr_tail.empty() ? "" : ": " + res.stderr_tail);
        LOG_ERROR("visualizer: {}", res.error);
        return res;
    }

    // The script prints the relative path of the HTML it produced on its
    // last non-empty stdout line. Both bounds are INCLUSIVE: substr() takes a
    // count, so count = end - start + 1 (an off-by-one here silently
    // truncated "a.html" to "a.htm", which then failed the existence check).
    std::string produced;
    {
        const std::string& out = r.std_out;
        const std::size_t end = out.find_last_not_of("\r\n \t");
        if (end != std::string::npos) {
            const std::size_t sep = out.find_last_of("\r\n", end);
            const std::size_t start = (sep == std::string::npos) ? 0 : (sep + 1);
            produced = out.substr(start, end - start + 1);
        }
    }

    if (produced.empty()) {
        res.error = "dashboard generator produced no output path";
        LOG_ERROR("visualizer: {}", res.error);
        return res;
    }

    if (!fs::exists(produced)) {
        res.error = "dashboard generator reported '" + produced +
                    "' but the file does not exist";
        LOG_ERROR("visualizer: {}", res.error);
        return res;
    }

    res.html_path  = produced;
    res.html_bytes = file_size_or_zero(produced);
    res.ok = true;

    LOG_INFO("visualizer: wrote '{}' ({} bytes) in {:.3f}s",
             res.html_path, res.html_bytes, res.seconds);
    return res;
}

}  // namespace visualizer