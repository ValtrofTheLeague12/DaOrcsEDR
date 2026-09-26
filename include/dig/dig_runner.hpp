#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

namespace dns_runner {

struct options {
  std::string wsl_distro;                 // empty = default WSL distro
  std::string nameserver;                 // empty = system resolver
  std::chrono::milliseconds timeout{10000};
  std::size_t max_output_bytes = 256u * 1024u;
};

struct answer_t {
  std::string name;
  std::string type;
  std::string value;
  std::string ttl;
};

struct result_t {
  std::string domain;
  std::string query_type = "A";
  std::string command;
  std::string response;
  std::string error;
  std::string status;                 // NOERROR, NXDOMAIN, SERVFAIL, ...
  std::vector<answer_t> answers;
  int         exit_code = -1;
  double      seconds = 0.0;
  bool        attempted = false;
  bool        answered = false;      // command completed and response was received
  bool        has_answer = false;     // at least one answer record was parsed
};

result_t query(const std::string& domain, const options& opts = {});

}  // namespace dns_runner