#include "dig_runner.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <sstream>
#include <string>
#include <vector>

#include "process_runner.hpp"

namespace dns_runner {

namespace {

std::string trim(std::string value) {
  while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ')) value.pop_back();
  while (!value.empty() && (value.front() == '\n' || value.front() == '\r' || value.front() == ' ')) value.erase(value.begin());
  return value;
}

std::vector<std::string> wsl_command(const options& opts) {
  std::vector<std::string> command{"wsl.exe"};
  if (!opts.wsl_distro.empty()) {
    command.push_back("-d");
    command.push_back(opts.wsl_distro);
  }
  return command;
}

void parse_response(result_t& result) {
  std::istringstream input(result.response);
  std::string line;
  bool in_answer_section = false;
  while (std::getline(input, line)) {
    line = trim(line);
    if (line.find("status:") != std::string::npos) {
      const std::size_t colon = line.find("status:");
      if (colon != std::string::npos) {
        std::string value = trim(line.substr(colon + 7));
        const std::size_t comma = value.find(',');
        if (comma != std::string::npos) value.resize(comma);
        result.status = value;
      }
    }
    if (line == ";; ANSWER SECTION:") { in_answer_section = true; continue; }
    if (in_answer_section && line.rfind(";;", 0) == 0) { in_answer_section = false; continue; }
    if (!in_answer_section || line.empty() || line.rfind(";", 0) == 0) continue;
    std::istringstream fields(line);
    answer_t answer;
    if (fields >> answer.name >> answer.ttl >> std::ws >> answer.type >> answer.value) {
      result.answers.push_back(answer);
    }
  }
  result.has_answer = !result.answers.empty();
}

}  // namespace

result_t query(const std::string& domain, const options& opts) {
  result_t result;
  result.domain = domain;
  result.attempted = true;
  if (domain.empty()) {
    result.error = "domain is empty";
    return result;
  }

  std::vector<std::string> command = wsl_command(opts);
  command.push_back("--");
  command.push_back("dig");
  if (!opts.nameserver.empty()) {
    command.push_back("@");
    command.push_back(opts.nameserver);
  }
  command.push_back(domain);
  command.push_back("A");
  command.push_back("+time=3");
  command.push_back("+tries=1");

  result.command = "wsl.exe";
  for (std::size_t i = 1; i < command.size(); ++i) {
    result.command += " ";
    result.command += command[i];
  }

  proc::run_options run_opts;
  run_opts.timeout = opts.timeout;
  run_opts.max_stdout_bytes = opts.max_output_bytes;
  run_opts.max_stderr_bytes = 64u * 1024u;
  const proc::run_result run = proc::run(command.front(),
                                         std::vector<std::string>(command.begin() + 1, command.end()),
                                         run_opts);
  result.exit_code = run.exit_code;
  result.seconds = run.seconds;
  result.response = trim(run.std_out);
  if (run.status != proc::launch_status::ok) {
    result.error = run.error.empty() ? proc::to_string(run.status) : run.error;
    return result;
  }
  if (run.exit_code != 0) {
    result.error = trim(run.std_err);
    if (result.error.empty()) result.error = "dig exited with code " + std::to_string(run.exit_code);
    return result;
  }
  if (result.response.empty()) {
    result.error = "no DNS response";
    return result;
  }
  parse_response(result);
  result.answered = true;
  return result;
}

}  // namespace dns_runner
