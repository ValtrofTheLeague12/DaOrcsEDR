#include "process_runner.hpp"
#include "logging.hpp"

#include <algorithm>
#include <atomic>      // ADDED
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>      // ADDED
#include <mutex>       // ADDED
#include <string>
#include <thread>      // ADDED
#include <vector>      // ADDED

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace proc {

const char* to_string(launch_status status) {
  switch (status) {
    case launch_status::ok:               return "ok";
    case launch_status::not_found:        return "not_found";
    case launch_status::launch_failed:    return "launch_failed";
    case launch_status::timed_out:        return "timed_out";
    case launch_status::output_too_large: return "output_too_large";
  }
  return "unknown";
}

namespace {

using clock_type = std::chrono::steady_clock;

double seconds_since(clock_type::time_point start) {
  return std::chrono::duration<double>(clock_type::now() - start).count();
}

}  
#if defined(_WIN32)

namespace {

bool has_dir_part(const std::string& name) {
  return name.find('/') != std::string::npos || name.find('\\') != std::string::npos;
}

std::wstring widen(const std::string& text) {
  if (text.empty()) return {};
  const int n = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                    nullptr, 0);
  if (n <= 0) return {};
  std::wstring out(static_cast<std::size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &out[0], n);
  return out;
}

bool file_exists(const std::wstring& path) {
  const DWORD attrs = GetFileAttributesW(path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool has_extension(const std::wstring& name) {
  const std::size_t dot = name.rfind(L'.');
  const std::size_t sep = name.find_last_of(L"\\/");
  return dot != std::wstring::npos && (sep == std::wstring::npos || dot > sep);
}

void append_quoted(std::wstring& cmd, const std::wstring& arg) {
  if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
    cmd += arg;
    return;
  }
  cmd += L'"';
  for (auto it = arg.begin();; ++it) {
    std::size_t backslashes = 0;
    while (it != arg.end() && *it == L'\\') {
      ++it;
      ++backslashes;
    }
    if (it == arg.end()) {
      cmd.append(backslashes * 2, L'\\');
      break;
    }
    if (*it == L'"') {
      cmd.append(backslashes * 2 + 1, L'\\');
      cmd.push_back(L'"');
    } else {
      cmd.append(backslashes, L'\\');
      cmd.push_back(*it);
    }
  }
  cmd += L'"';
}

std::wstring build_environment(const std::vector<std::string>& extra) {
  std::vector<std::wstring> entries;
  if (LPWCH block = GetEnvironmentStringsW()) {
    for (const wchar_t* p = block; *p != L'\0'; p += wcslen(p) + 1) entries.emplace_back(p);
    FreeEnvironmentStringsW(block);
  }
  for (const std::string& item : extra) {
    const std::wstring wide = widen(item);
    const std::size_t eq = wide.find(L'=');
    if (eq == std::wstring::npos || eq == 0) continue;
    const std::wstring key = wide.substr(0, eq + 1);
    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [&](const std::wstring& e) {
                                   return e.size() >= key.size() &&
                                          _wcsnicmp(e.c_str(), key.c_str(), key.size()) == 0;
                                 }),
                  entries.end());
    entries.push_back(wide);
  }
  std::sort(entries.begin(), entries.end(), [](const std::wstring& a, const std::wstring& b) {
    return _wcsicmp(a.c_str(), b.c_str()) < 0;
  });
  std::wstring block;
  for (const std::wstring& e : entries) {
    block += e;
    block.push_back(L'\0');
  }
  block.push_back(L'\0');
  return block;
}

struct pipe_reader {
  HANDLE      handle = nullptr;
  HANDLE      thread = nullptr;
  std::string data;
  std::size_t cap        = 0;
  bool        truncated  = false;
  volatile LONG overflow = 0;
};

DWORD WINAPI reader_main(LPVOID param) {
  auto* reader = static_cast<pipe_reader*>(param);
  std::vector<char> buffer(64 * 1024);
  DWORD got = 0;
  while (ReadFile(reader->handle, buffer.data(), static_cast<DWORD>(buffer.size()), &got,
                  nullptr) &&
         got > 0) {
    const std::size_t room = reader->cap > reader->data.size() ? reader->cap - reader->data.size() : 0;
    const std::size_t take = std::min<std::size_t>(room, got);
    if (take > 0) reader->data.append(buffer.data(), take);
    if (take < got) {
      reader->truncated = true;
      InterlockedExchange(&reader->overflow, 1);
    }
  }
  return 0;
}

std::string last_error_text(DWORD code) {
  char* message = nullptr;
  const DWORD n = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, 0, reinterpret_cast<LPSTR>(&message), 0, nullptr);
  std::string text = "error " + std::to_string(code);
  if (n != 0 && message != nullptr) {
    std::string detail(message, n);
    while (!detail.empty() && (detail.back() == '\r' || detail.back() == '\n' || detail.back() == ' '))
      detail.pop_back();
    text += ": " + detail;
  }
  if (message != nullptr) LocalFree(message);
  return text;
}

void close_handle(HANDLE& handle) {
  if (handle != nullptr && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
  handle = nullptr;
}

}  // namespace

std::string find_in_path(const std::string& name) {
  LOG_TRACE("proc: find_in_path('{}')", name);
  if (name.empty()) return {};
  const std::wstring wide = widen(name);
  static const wchar_t* const kExtensions[] = {L".exe", L".com"};

  auto try_dir = [&](const std::wstring& dir) -> std::wstring {
    std::wstring base = dir;
    if (!base.empty() && base.back() != L'\\' && base.back() != L'/') base += L'\\';
    base += wide;
    if (has_extension(wide)) return file_exists(base) ? base : std::wstring();
    for (const wchar_t* ext : kExtensions) {
      if (file_exists(base + ext)) return base + ext;
    }
    return {};
  };

  auto to_utf8 = [](const std::wstring& w) {
    if (w.empty()) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0,
                                      nullptr, nullptr);
    std::string out(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), &out[0], n, nullptr,
                        nullptr);
    return out;
  };

  if (has_dir_part(name) || (wide.size() > 1 && wide[1] == L':')) {
    if (has_extension(wide)) return file_exists(wide) ? name : std::string();
    for (const wchar_t* ext : kExtensions) {
      if (file_exists(wide + ext)) return to_utf8(wide + ext);
    }
    return {};
  }

  const DWORD needed = GetEnvironmentVariableW(L"PATH", nullptr, 0);
  if (needed == 0) return {};
  std::wstring path(needed, L'\0');
  const DWORD got = GetEnvironmentVariableW(L"PATH", &path[0], needed);
  path.resize(got);

  std::size_t start = 0;
  while (start <= path.size()) {
    std::size_t end = path.find(L';', start);
    if (end == std::wstring::npos) end = path.size();
    std::wstring dir = path.substr(start, end - start);
    if (dir.size() >= 2 && dir.front() == L'"' && dir.back() == L'"') dir = dir.substr(1, dir.size() - 2);
    if (!dir.empty()) {
      const std::wstring hit = try_dir(dir);
      if (!hit.empty()) {
        const std::string out = to_utf8(hit);
        LOG_TRACE("proc: find_in_path('{}') -> '{}'", name, out);
        return out;
      }
    }
    start = end + 1;
  }
  LOG_DEBUG("proc: find_in_path('{}') -> not found", name);
  return {};
}

run_result run(const std::string& program, const std::vector<std::string>& args,
               const run_options& options) {
  run_result result;
  const auto started = clock_type::now();

  LOG_DEBUG("proc: run: launching '{}' with {} argument(s)", program, args.size());

  const std::string resolved = find_in_path(program);
  if (resolved.empty()) {
    LOG_WARN("proc: run: executable not found: '{}'", program);
    result.status = launch_status::not_found;
    result.error = "executable not found: " + program;
    return result;
  }

  std::wstring command_line;
  append_quoted(command_line, widen(resolved));
  for (const std::string& arg : args) {
    command_line += L' ';
    append_quoted(command_line, widen(arg));
  }
  command_line.push_back(L'\0');

  LOG_TRACE("proc: run: resolved='{}', command_line_length={}",
            resolved, command_line.size());

  // Pipes: parent keeps the read ends (non-inheritable), the child gets the write ends.
  SECURITY_ATTRIBUTES inherit{};
  inherit.nLength = sizeof(inherit);
  inherit.bInheritHandle = TRUE;

  HANDLE out_read = nullptr, out_write = nullptr, err_read = nullptr, err_write = nullptr;
  HANDLE nul = nullptr;
  auto cleanup_pipes = [&]() {
    close_handle(out_read);
    close_handle(out_write);
    close_handle(err_read);
    close_handle(err_write);
    close_handle(nul);
  };

  if (!CreatePipe(&out_read, &out_write, &inherit, 0) ||
      !CreatePipe(&err_read, &err_write, &inherit, 0)) {
    const DWORD err = GetLastError();
    LOG_ERROR("proc: run: CreatePipe failed for '{}': {}",
              resolved, last_error_text(err));
    result.status = launch_status::launch_failed;
    result.error = "CreatePipe failed: " + last_error_text(err);
    cleanup_pipes();
    return result;
  }
  SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);
  nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

  // Only these three handles may be inherited (other threads can be creating
  // inheritable handles at the same time).
  HANDLE inherit_list[3] = {nul, out_write, err_write};
  const DWORD inherit_count = (nul != INVALID_HANDLE_VALUE && nul != nullptr) ? 3 : 2;
  HANDLE* list_ptr = inherit_count == 3 ? inherit_list : &inherit_list[1];

  SIZE_T attr_size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
  std::vector<char> attr_storage(attr_size);
  auto* attr_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_storage.data());
  bool have_attr_list = attr_size != 0 && InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size);
  if (have_attr_list &&
      !UpdateProcThreadAttribute(attr_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list_ptr,
                                 inherit_count * sizeof(HANDLE), nullptr, nullptr)) {
    DeleteProcThreadAttributeList(attr_list);
    have_attr_list = false;
  }
  LOG_TRACE("proc: run: handle inheritance list={} ({} handles)",
            have_attr_list, inherit_count);

  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = have_attr_list ? sizeof(STARTUPINFOEXW) : sizeof(STARTUPINFOW);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = (inherit_count == 3) ? nul : INVALID_HANDLE_VALUE;
  startup.StartupInfo.hStdOutput = out_write;
  startup.StartupInfo.hStdError = err_write;
  startup.lpAttributeList = have_attr_list ? attr_list : nullptr;

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (job != nullptr) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
  } else {
    LOG_DEBUG("proc: run: CreateJobObject failed (err={}), will fall back to TerminateProcess",
              last_error_text(GetLastError()));
  }

  DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
  if (have_attr_list) flags |= EXTENDED_STARTUPINFO_PRESENT;
  if (options.low_priority) flags |= BELOW_NORMAL_PRIORITY_CLASS;

  std::wstring environment;
  LPVOID environment_ptr = nullptr;
  if (!options.extra_env.empty()) {
    environment = build_environment(options.extra_env);
    environment_ptr = &environment[0];
  }
  const std::wstring working_dir = widen(options.working_dir);

  PROCESS_INFORMATION info{};
  const BOOL created = CreateProcessW(widen(resolved).c_str(), &command_line[0], nullptr, nullptr,
                                      TRUE, flags, environment_ptr,
                                      working_dir.empty() ? nullptr : working_dir.c_str(),
                                      reinterpret_cast<LPSTARTUPINFOW>(&startup), &info);
  const DWORD create_error = created ? 0 : GetLastError();
  if (have_attr_list) DeleteProcThreadAttributeList(attr_list);

  // The parent must drop its copies of the write ends or EOF never arrives.
  close_handle(out_write);
  close_handle(err_write);
  close_handle(nul);

  if (!created) {
    LOG_ERROR("proc: run: CreateProcess failed for '{}': {}",
              resolved, last_error_text(create_error));
    result.status = (create_error == ERROR_FILE_NOT_FOUND || create_error == ERROR_PATH_NOT_FOUND ||
                     create_error == ERROR_ACCESS_DENIED || create_error == ERROR_BAD_EXE_FORMAT)
                        ? launch_status::not_found
                        : launch_status::launch_failed;
    result.error = "CreateProcess failed for '" + resolved + "': " + last_error_text(create_error);
    close_handle(out_read);
    close_handle(err_read);
    close_handle(job);
    return result;
  }

  LOG_TRACE("proc: run: child pid={}", info.dwProcessId);

  if (job != nullptr && !AssignProcessToJobObject(job, info.hProcess)) {
    LOG_DEBUG("proc: run: AssignProcessToJobObject failed (err={}), "
              "will fall back to TerminateProcess",
              last_error_text(GetLastError()));
    close_handle(job);  // e.g. already inside a job without nesting support: still works
  }

  pipe_reader out_reader, err_reader;
  out_reader.handle = out_read;
  out_reader.cap = options.max_stdout_bytes;
  err_reader.handle = err_read;
  err_reader.cap = options.max_stderr_bytes;
  out_reader.thread = CreateThread(nullptr, 0, reader_main, &out_reader, 0, nullptr);
  err_reader.thread = CreateThread(nullptr, 0, reader_main, &err_reader, 0, nullptr);

  ResumeThread(info.hThread);

  launch_status status = launch_status::ok;
  const bool has_timeout = options.timeout.count() > 0;
  const auto deadline = started + options.timeout;

  auto kill_tree = [&](const char* reason) {
    LOG_DEBUG("proc: run: killing child tree pid={} ({})", info.dwProcessId, reason);
    if (job != nullptr) TerminateJobObject(job, 1);
    else TerminateProcess(info.hProcess, 1);
  };

  for (;;) {
    if (WaitForSingleObject(info.hProcess, 50) == WAIT_OBJECT_0) break;
    if (out_reader.overflow) {
      LOG_WARN("proc: run: stdout exceeded cap ({} bytes) for pid={}",
               options.max_stdout_bytes, info.dwProcessId);
      status = launch_status::output_too_large;
      kill_tree("stdout overflow");
      break;
    }
    if (has_timeout && clock_type::now() >= deadline) {
      LOG_WARN("proc: run: timeout ({} ms) exceeded for pid={}",
               options.timeout.count(), info.dwProcessId);
      status = launch_status::timed_out;
      kill_tree("timeout");
      break;
    }
  }
  WaitForSingleObject(info.hProcess, 10000);

  DWORD exit_code = 0;
  GetExitCodeProcess(info.hProcess, &exit_code);
  result.exit_code = static_cast<int>(exit_code);

  // Readers end on EOF. If a grandchild outside the job still holds the pipe, do not hang.
  for (pipe_reader* reader : {&out_reader, &err_reader}) {
    if (WaitForSingleObject(reader->thread, 3000) != WAIT_OBJECT_0) {
      LOG_DEBUG("proc: run: reader thread did not exit on EOF, cancelling");
      CancelSynchronousIo(reader->thread);
      WaitForSingleObject(reader->thread, 2000);
    }
    close_handle(reader->thread);
    close_handle(reader->handle);
  }

  close_handle(info.hThread);
  close_handle(info.hProcess);
  close_handle(job);

  result.status = status;
  result.std_out = std::move(out_reader.data);
  result.std_err = std::move(err_reader.data);
  result.stderr_truncated = err_reader.truncated;
  if (status == launch_status::timed_out) {
    result.error = "timed out after " + std::to_string(options.timeout.count() / 1000) + " s";
  } else if (status == launch_status::output_too_large) {
    result.error = "stdout exceeded " + std::to_string(options.max_stdout_bytes) + " bytes";
  }
  result.seconds = seconds_since(started);

  LOG_INFO("proc: run: '{}' finished status={} exit={} in {:.3f}s "
           "(stdout={} B{}, stderr={} B{})",
           resolved, to_string(result.status), result.exit_code, result.seconds,
           result.std_out.size(), result.stderr_truncated ? "/truncated" : "",
           result.std_err.size(), result.stderr_truncated ? "/truncated" : "");

  return result;
}

#else

namespace {

bool is_executable_file(const std::string& path) {
  struct stat st{};
  return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode) && ::access(path.c_str(), X_OK) == 0;
}

void set_cloexec(int fd) {
  const int flags = ::fcntl(fd, F_GETFD);
  if (flags >= 0) ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

void close_fd(int& fd) {
  if (fd >= 0) ::close(fd);
  fd = -1;
}

void kill_group(pid_t pid) {
  LOG_DEBUG("proc: kill_group: pid={}", static_cast<int>(pid));
  ::kill(-pid, SIGKILL);  // the child is its own process-group leader
  ::kill(pid, SIGKILL);
}

std::vector<std::string> build_environment(const std::vector<std::string>& extra) {
  std::vector<std::string> entries;
  for (char** e = environ; e != nullptr && *e != nullptr; ++e) entries.emplace_back(*e);
  for (const std::string& item : extra) {
    const std::size_t eq = item.find('=');
    if (eq == std::string::npos || eq == 0) continue;
    const std::string key = item.substr(0, eq + 1);
    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [&](const std::string& e) { return e.compare(0, key.size(), key) == 0; }),
                  entries.end());
    entries.push_back(item);
  }
  return entries;
}

}  // namespace

std::string find_in_path(const std::string& name) {
  LOG_TRACE("proc: find_in_path('{}')", name);
  if (name.empty()) return {};
  if (name.find('/') != std::string::npos) {
    const bool ok = is_executable_file(name);
    LOG_TRACE("proc: find_in_path('{}') -> {} (explicit path)", name, ok ? name : "(not found)");
    return ok ? name : std::string();
  }

  const char* path_env = std::getenv("PATH");
  const std::string path = path_env != nullptr ? path_env : "/usr/local/bin:/usr/bin:/bin";
  std::size_t start = 0;
  while (start <= path.size()) {
    std::size_t end = path.find(':', start);
    if (end == std::string::npos) end = path.size();
    std::string dir = path.substr(start, end - start);
    if (dir.empty()) dir = ".";
    const std::string candidate = dir + "/" + name;
    if (is_executable_file(candidate)) {
      LOG_TRACE("proc: find_in_path('{}') -> '{}'", name, candidate);
      return candidate;
    }
    start = end + 1;
  }
  LOG_DEBUG("proc: find_in_path('{}') -> not found", name);
  return {};
}

run_result run(const std::string& program, const std::vector<std::string>& args,
               const run_options& options) {
  run_result result;
  const auto started = clock_type::now();

  LOG_DEBUG("proc: run: launching '{}' with {} argument(s)", program, args.size());

  const std::string resolved = find_in_path(program);
  if (resolved.empty()) {
    LOG_WARN("proc: run: executable not found: '{}'", program);
    result.status = launch_status::not_found;
    result.error = "executable not found: " + program;
    return result;
  }

  // Everything the child needs is prepared BEFORE fork(): only async-signal-safe
  // calls may run between fork() and exec().
  std::vector<std::string> argv_storage;
  argv_storage.push_back(resolved);
  argv_storage.insert(argv_storage.end(), args.begin(), args.end());
  std::vector<char*> argv;
  for (std::string& a : argv_storage) argv.push_back(&a[0]);
  argv.push_back(nullptr);

  std::vector<std::string> env_storage = build_environment(options.extra_env);
  std::vector<char*> envp;
  for (std::string& e : env_storage) envp.push_back(&e[0]);
  envp.push_back(nullptr);

  int out_pipe[2] = {-1, -1}, err_pipe[2] = {-1, -1}, exec_pipe[2] = {-1, -1};
  if (::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0 || ::pipe(exec_pipe) != 0) {
    const int err = errno;
    LOG_ERROR("proc: run: pipe() failed for '{}': {}", resolved, std::strerror(err));
    result.status = launch_status::launch_failed;
    result.error = std::string("pipe() failed: ") + std::strerror(err);
    for (int* p : {out_pipe, err_pipe, exec_pipe}) {
      close_fd(p[0]);
      close_fd(p[1]);
    }
    return result;
  }
  set_cloexec(out_pipe[0]);
  set_cloexec(err_pipe[0]);
  set_cloexec(exec_pipe[0]);
  set_cloexec(exec_pipe[1]);  // closes on a successful exec => parent reads EOF

  const int null_fd = ::open("/dev/null", O_RDONLY);
  if (null_fd < 0) {
    LOG_DEBUG("proc: run: could not open /dev/null ({}), child will inherit parent stdin",
              std::strerror(errno));
  }
  const char* cwd = options.working_dir.empty() ? nullptr : options.working_dir.c_str();
  const bool low_priority = options.low_priority;

  const pid_t pid = ::fork();
  if (pid < 0) {
    const int err = errno;
    LOG_ERROR("proc: run: fork() failed for '{}': {}", resolved, std::strerror(err));
    result.status = launch_status::launch_failed;
    result.error = std::string("fork() failed: ") + std::strerror(err);
    for (int* p : {out_pipe, err_pipe, exec_pipe}) {
      close_fd(p[0]);
      close_fd(p[1]);
    }
    if (null_fd >= 0) ::close(null_fd);
    return result;
  }

  if (pid == 0) {  // ------------------------------ child
    ::setpgid(0, 0);
    if (null_fd >= 0) ::dup2(null_fd, STDIN_FILENO);
    ::dup2(out_pipe[1], STDOUT_FILENO);
    ::dup2(err_pipe[1], STDERR_FILENO);
    if (cwd != nullptr && ::chdir(cwd) != 0) {
      const int e = errno;
      (void)!::write(exec_pipe[1], &e, sizeof(e));
      ::_exit(127);
    }
    if (low_priority) ::setpriority(PRIO_PROCESS, 0, 10);
    ::execve(argv[0], argv.data(), envp.data());
    const int e = errno;
    (void)!::write(exec_pipe[1], &e, sizeof(e));
    ::_exit(127);
  }

  // ------------------------------------------------ parent
  LOG_TRACE("proc: run: fork returned pid={}", static_cast<int>(pid));

  ::setpgid(pid, pid);  // also done by the child; avoids the race
  close_fd(out_pipe[1]);
  close_fd(err_pipe[1]);
  close_fd(exec_pipe[1]);
  if (null_fd >= 0) ::close(null_fd);

  int exec_errno = 0;
  ssize_t n;
  do {
    n = ::read(exec_pipe[0], &exec_errno, sizeof(exec_errno));
  } while (n < 0 && errno == EINTR);
  close_fd(exec_pipe[0]);

  if (n == static_cast<ssize_t>(sizeof(exec_errno))) {  // exec failed
    LOG_ERROR("proc: run: execve failed for '{}': {}",
              resolved, std::strerror(exec_errno));
    int wait_status = 0;
    ::waitpid(pid, &wait_status, 0);
    close_fd(out_pipe[0]);
    close_fd(err_pipe[0]);
    result.status = (exec_errno == ENOENT || exec_errno == EACCES || exec_errno == ENOTDIR ||
                     exec_errno == ENOEXEC)
                        ? launch_status::not_found
                        : launch_status::launch_failed;
    result.error = "cannot execute '" + resolved + "': " + std::strerror(exec_errno);
    return result;
  }

  int fds[2] = {out_pipe[0], err_pipe[0]};
  std::string* sinks[2] = {&result.std_out, &result.std_err};
  const std::size_t caps[2] = {options.max_stdout_bytes, options.max_stderr_bytes};

  launch_status status = launch_status::ok;
  const bool has_timeout = options.timeout.count() > 0;
  const auto deadline = started + options.timeout;
  std::vector<char> buffer(64 * 1024);

  while (fds[0] >= 0 || fds[1] >= 0) {
    int wait_ms = -1;
    if (has_timeout) {
      const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
      if (left.count() <= 0) {
        LOG_WARN("proc: run: timeout ({} ms) exceeded while reading pipes for pid={}",
                 options.timeout.count(), static_cast<int>(pid));
        status = launch_status::timed_out;
        break;
      }
      wait_ms = static_cast<int>(std::min<long long>(left.count(), 1000));
    }

    pollfd pfds[2];
    for (int i = 0; i < 2; ++i) {
      pfds[i].fd = fds[i];  // negative fds are ignored by poll()
      pfds[i].events = POLLIN;
      pfds[i].revents = 0;
    }
    const int ready = ::poll(pfds, 2, wait_ms);
    if (ready < 0) {
      if (errno == EINTR) continue;
      LOG_DEBUG("proc: run: poll() failed for pid={}: {}",
                static_cast<int>(pid), std::strerror(errno));
      break;
    }
    for (int i = 0; i < 2; ++i) {
      if (fds[i] < 0 || (pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;
      const ssize_t got = ::read(fds[i], buffer.data(), buffer.size());
      if (got > 0) {
        const std::size_t room = caps[i] > sinks[i]->size() ? caps[i] - sinks[i]->size() : 0;
        const std::size_t take = std::min<std::size_t>(room, static_cast<std::size_t>(got));
        if (take > 0) sinks[i]->append(buffer.data(), take);
        if (take < static_cast<std::size_t>(got)) {
          if (i == 0) {
            LOG_WARN("proc: run: stdout exceeded cap ({} bytes) for pid={}",
                     options.max_stdout_bytes, static_cast<int>(pid));
            status = launch_status::output_too_large;
          } else {
            LOG_DEBUG("proc: run: stderr truncated at {} bytes for pid={}",
                      options.max_stderr_bytes, static_cast<int>(pid));
            result.stderr_truncated = true;
          }
        }
      } else if (got == 0 || (got < 0 && errno != EINTR && errno != EAGAIN)) {
        close_fd(fds[i]);
      }
    }
    if (status == launch_status::output_too_large) break;
  }

  int wait_status = 0;
  if (status != launch_status::ok) {
    kill_group(pid);
    ::waitpid(pid, &wait_status, 0);
  } else {
    // Both pipes are closed; the process normally exits right away.
    for (;;) {
      const pid_t done = ::waitpid(pid, &wait_status, WNOHANG);
      if (done == pid) break;
      if (done < 0 && errno != EINTR) break;
      if (has_timeout && clock_type::now() >= deadline) {
        LOG_WARN("proc: run: timeout ({} ms) exceeded while waiting for pid={}",
                 options.timeout.count(), static_cast<int>(pid));
        status = launch_status::timed_out;
        kill_group(pid);
        ::waitpid(pid, &wait_status, 0);
        break;
      }
      ::usleep(2000);
    }
  }
  close_fd(fds[0]);
  close_fd(fds[1]);

  if (WIFEXITED(wait_status)) result.exit_code = WEXITSTATUS(wait_status);
  else if (WIFSIGNALED(wait_status)) {
    result.exit_code = 128 + WTERMSIG(wait_status);
    LOG_DEBUG("proc: run: pid={} terminated by signal {}",
              static_cast<int>(pid), WTERMSIG(wait_status));
  }

  result.status = status;
  if (status == launch_status::timed_out) {
    result.error = "timed out after " + std::to_string(options.timeout.count() / 1000) + " s";
  } else if (status == launch_status::output_too_large) {
    result.error = "stdout exceeded " + std::to_string(options.max_stdout_bytes) + " bytes";
  }
  result.seconds = seconds_since(started);

  LOG_INFO("proc: run: '{}' finished status={} exit={} in {:.3f}s "
           "(stdout={} B{}, stderr={} B{})",
           resolved, to_string(result.status), result.exit_code, result.seconds,
           result.std_out.size(), result.stderr_truncated ? "/truncated" : "",
           result.std_err.size(), result.stderr_truncated ? "/truncated" : "");

  return result;
}

#endif  // _WIN32

// =============================================================================
// ADDED: proc::child implementation
//
// Shares the file-scope helpers already defined above:
//   Windows: widen, append_quoted, build_environment, pipe_reader,
//            reader_main, close_handle, last_error_text, find_in_path
//   POSIX  : is_executable_file, set_cloexec, close_fd, kill_group,
//            build_environment, find_in_path
// run() and everything above is untouched.
// =============================================================================

struct child::impl {
  std::atomic<bool> alive{false};
  std::uint64_t     pid_value = 0;
  int               exit_code_value = -1;

  mutable std::mutex mtx;
  std::string        out_buf;
  std::string        err_buf;

#if defined(_WIN32)
  HANDLE      job    = nullptr;
  HANDLE      proc   = nullptr;
  HANDLE      thread = nullptr;
  pipe_reader out_reader;
  pipe_reader err_reader;
#else
  pid_t       pid    = -1;
  int         out_fd = -1;
  int         err_fd = -1;
  std::thread out_thread;
  std::thread err_thread;
#endif

  ~impl() { kill(); }

  launch_status start(const std::string& program,
                      const std::vector<std::string>& args,
                      const run_options& options) {
    if (alive.load()) {
      LOG_WARN("proc: child::start called while pid={} is still alive",
               pid_value);
      return launch_status::launch_failed;
    }

    const std::string resolved = find_in_path(program);
    if (resolved.empty()) {
      LOG_WARN("proc: child: executable not found: '{}'", program);
      return launch_status::not_found;
    }

    LOG_DEBUG("proc: child: launching '{}' with {} argument(s)",
              resolved, args.size());

#if defined(_WIN32)
    std::wstring command_line;
    append_quoted(command_line, widen(resolved));
    for (const std::string& arg : args) {
      command_line += L' ';
      append_quoted(command_line, widen(arg));
    }
    command_line.push_back(L'\0');

    SECURITY_ATTRIBUTES inherit{};
    inherit.nLength        = sizeof(inherit);
    inherit.bInheritHandle = TRUE;

    HANDLE out_read = nullptr, out_write = nullptr;
    HANDLE err_read = nullptr, err_write = nullptr;
    HANDLE nul = nullptr;
    auto cleanup_pipes = [&]() {
      close_handle(out_read);  close_handle(out_write);
      close_handle(err_read);  close_handle(err_write);
      close_handle(nul);
    };

    if (!CreatePipe(&out_read, &out_write, &inherit, 0) ||
        !CreatePipe(&err_read, &err_write, &inherit, 0)) {
      const DWORD err = GetLastError();
      LOG_ERROR("proc: child: CreatePipe failed for '{}': {}",
                resolved, last_error_text(err));
      cleanup_pipes();
      return launch_status::launch_failed;
    }
    SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);
    nul = CreateFileW(L"NUL", GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    HANDLE inherit_list[3] = {nul, out_write, err_write};
    const DWORD inherit_count =
        (nul != INVALID_HANDLE_VALUE && nul != nullptr) ? 3 : 2;
    HANDLE* list_ptr = inherit_count == 3 ? inherit_list : &inherit_list[1];

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    std::vector<char> attr_storage(attr_size);
    auto* attr_list =
        reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_storage.data());
    bool have_attr_list =
        attr_size != 0 &&
        InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size);
    if (have_attr_list &&
        !UpdateProcThreadAttribute(
            attr_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list_ptr,
            inherit_count * sizeof(HANDLE), nullptr, nullptr)) {
      DeleteProcThreadAttributeList(attr_list);
      have_attr_list = false;
    }

    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb =
        have_attr_list ? sizeof(STARTUPINFOEXW) : sizeof(STARTUPINFOW);
    startup.StartupInfo.dwFlags    = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput  = (inherit_count == 3)
                                         ? nul
                                         : INVALID_HANDLE_VALUE;
    startup.StartupInfo.hStdOutput = out_write;
    startup.StartupInfo.hStdError  = err_write;
    startup.lpAttributeList        = have_attr_list ? attr_list : nullptr;

    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job != nullptr) {
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
      limits.BasicLimitInformation.LimitFlags =
          JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                              &limits, sizeof(limits));
    } else {
      LOG_DEBUG("proc: child: CreateJobObject failed (err={}), will fall "
                "back to TerminateProcess",
                last_error_text(GetLastError()));
    }

    DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    if (have_attr_list) flags |= EXTENDED_STARTUPINFO_PRESENT;
    if (options.low_priority) flags |= BELOW_NORMAL_PRIORITY_CLASS;

    std::wstring environment;
    LPVOID environment_ptr = nullptr;
    if (!options.extra_env.empty()) {
      environment = build_environment(options.extra_env);
      environment_ptr = &environment[0];
    }
    const std::wstring working_dir = widen(options.working_dir);

    PROCESS_INFORMATION info{};
    const BOOL created = CreateProcessW(
        widen(resolved).c_str(), &command_line[0], nullptr, nullptr,
        TRUE, flags, environment_ptr,
        working_dir.empty() ? nullptr : working_dir.c_str(),
        reinterpret_cast<LPSTARTUPINFOW>(&startup), &info);
    const DWORD create_error = created ? 0 : GetLastError();
    if (have_attr_list) DeleteProcThreadAttributeList(attr_list);

    close_handle(out_write);
    close_handle(err_write);
    close_handle(nul);

    if (!created) {
      LOG_ERROR("proc: child: CreateProcess failed for '{}': {}",
                resolved, last_error_text(create_error));
      close_handle(out_read);
      close_handle(err_read);
      close_handle(job);
      return (create_error == ERROR_FILE_NOT_FOUND ||
              create_error == ERROR_PATH_NOT_FOUND ||
              create_error == ERROR_ACCESS_DENIED ||
              create_error == ERROR_BAD_EXE_FORMAT)
                 ? launch_status::not_found
                 : launch_status::launch_failed;
    }

    LOG_TRACE("proc: child: pid={}", info.dwProcessId);

    if (job != nullptr &&
        !AssignProcessToJobObject(job, info.hProcess)) {
      LOG_DEBUG("proc: child: AssignProcessToJobObject failed (err={}), "
                "will fall back to TerminateProcess",
                last_error_text(GetLastError()));
      close_handle(job);
      job = nullptr;
    }

    out_reader.handle = out_read;
    out_reader.cap    = options.max_stdout_bytes;
    err_reader.handle = err_read;
    err_reader.cap    = options.max_stderr_bytes;
    out_reader.thread =
        CreateThread(nullptr, 0, reader_main, &out_reader, 0, nullptr);
    err_reader.thread =
        CreateThread(nullptr, 0, reader_main, &err_reader, 0, nullptr);

    this->job    = job;
    this->proc   = info.hProcess;
    this->thread = info.hThread;
    pid_value    = static_cast<std::uint64_t>(info.dwProcessId);
    alive.store(true);

    LOG_INFO("proc: child: started '{}' pid={}", resolved, pid_value);
    return launch_status::ok;
#else
    std::vector<std::string> argv_storage;
    argv_storage.push_back(resolved);
    argv_storage.insert(argv_storage.end(), args.begin(), args.end());
    std::vector<char*> argv;
    for (std::string& a : argv_storage) argv.push_back(&a[0]);
    argv.push_back(nullptr);

    std::vector<std::string> env_storage =
        build_environment(options.extra_env);
    std::vector<char*> envp;
    for (std::string& e : env_storage) envp.push_back(&e[0]);
    envp.push_back(nullptr);

    int out_pipe[2]  = {-1, -1};
    int err_pipe[2]  = {-1, -1};
    int exec_pipe[2] = {-1, -1};
    if (::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0 ||
        ::pipe(exec_pipe) != 0) {
      const int err = errno;
      LOG_ERROR("proc: child: pipe() failed for '{}': {}",
                resolved, std::strerror(err));
      for (int* p : {out_pipe, err_pipe, exec_pipe}) {
        close_fd(p[0]);
        close_fd(p[1]);
      }
      return launch_status::launch_failed;
    }
    set_cloexec(out_pipe[0]);
    set_cloexec(err_pipe[0]);
    set_cloexec(exec_pipe[0]);
    set_cloexec(exec_pipe[1]);

    const int null_fd = ::open("/dev/null", O_RDONLY);
    const char* cwd =
        options.working_dir.empty() ? nullptr : options.working_dir.c_str();
    const bool low_priority = options.low_priority;

    const pid_t pid = ::fork();
    if (pid < 0) {
      const int err = errno;
      LOG_ERROR("proc: child: fork() failed for '{}': {}",
                resolved, std::strerror(err));
      for (int* p : {out_pipe, err_pipe, exec_pipe}) {
        close_fd(p[0]);
        close_fd(p[1]);
      }
      if (null_fd >= 0) ::close(null_fd);
      return launch_status::launch_failed;
    }

    if (pid == 0) {  // child
      ::setpgid(0, 0);
      if (null_fd >= 0) ::dup2(null_fd, STDIN_FILENO);
      ::dup2(out_pipe[1], STDOUT_FILENO);
      ::dup2(err_pipe[1], STDERR_FILENO);
      if (cwd != nullptr && ::chdir(cwd) != 0) {
        const int e = errno;
        (void)!::write(exec_pipe[1], &e, sizeof(e));
        ::_exit(127);
      }
      if (low_priority) ::setpriority(PRIO_PROCESS, 0, 10);
      ::execve(argv[0], argv.data(), envp.data());
      const int e = errno;
      (void)!::write(exec_pipe[1], &e, sizeof(e));
      ::_exit(127);
    }

    ::setpgid(pid, pid);
    close_fd(out_pipe[1]);
    close_fd(err_pipe[1]);
    close_fd(exec_pipe[1]);
    if (null_fd >= 0) ::close(null_fd);

    int exec_errno = 0;
    ssize_t n;
    do {
      n = ::read(exec_pipe[0], &exec_errno, sizeof(exec_errno));
    } while (n < 0 && errno == EINTR);
    close_fd(exec_pipe[0]);

    if (n == static_cast<ssize_t>(sizeof(exec_errno))) {
      LOG_ERROR("proc: child: execve failed for '{}': {}",
                resolved, std::strerror(exec_errno));
      int wait_status = 0;
      ::waitpid(pid, &wait_status, 0);
      close_fd(out_pipe[0]);
      close_fd(err_pipe[0]);
      return (exec_errno == ENOENT || exec_errno == EACCES ||
              exec_errno == ENOTDIR || exec_errno == ENOEXEC)
                 ? launch_status::not_found
                 : launch_status::launch_failed;
    }

    out_fd = out_pipe[0];
    err_fd = err_pipe[0];

    out_thread = std::thread([this, cap = options.max_stdout_bytes]() {
      std::vector<char> buffer(64 * 1024);
      for (;;) {
        const ssize_t got = ::read(out_fd, buffer.data(), buffer.size());
        if (got > 0) {
          std::lock_guard<std::mutex> lock(mtx);
          const std::size_t room =
              out_buf.size() < cap ? cap - out_buf.size() : 0;
          const std::size_t take =
              std::min(room, static_cast<std::size_t>(got));
          if (take > 0) out_buf.append(buffer.data(), take);
        } else if (got == 0) {
          break;
        } else if (errno != EINTR && errno != EAGAIN) {
          break;
        }
      }
    });
    err_thread = std::thread([this, cap = options.max_stderr_bytes]() {
      std::vector<char> buffer(64 * 1024);
      for (;;) {
        const ssize_t got = ::read(err_fd, buffer.data(), buffer.size());
        if (got > 0) {
          std::lock_guard<std::mutex> lock(mtx);
          const std::size_t room =
              err_buf.size() < cap ? cap - err_buf.size() : 0;
          const std::size_t take =
              std::min(room, static_cast<std::size_t>(got));
          if (take > 0) err_buf.append(buffer.data(), take);
        } else if (got == 0) {
          break;
        } else if (errno != EINTR && errno != EAGAIN) {
          break;
        }
      }
    });

    this->pid = pid;
    pid_value = static_cast<std::uint64_t>(pid);
    alive.store(true);

    LOG_INFO("proc: child: started '{}' pid={}", resolved, pid_value);
    return launch_status::ok;
#endif
  }

  void kill() {
    if (!alive.exchange(false)) return;

    LOG_DEBUG("proc: child: killing pid={}", pid_value);

#if defined(_WIN32)
    if (job != nullptr) {
      TerminateJobObject(job, 1);
    } else if (proc != nullptr) {
      TerminateProcess(proc, 1);
    }
    if (proc != nullptr) {
      WaitForSingleObject(proc, 10000);
      DWORD code = 0;
      GetExitCodeProcess(proc, &code);
      exit_code_value = static_cast<int>(code);
    }
    for (pipe_reader* r : {&out_reader, &err_reader}) {
      if (r->thread != nullptr) {
        if (WaitForSingleObject(r->thread, 3000) != WAIT_OBJECT_0) {
          CancelSynchronousIo(r->thread);
          WaitForSingleObject(r->thread, 2000);
        }
        close_handle(r->thread);
      }
      close_handle(r->handle);
    }
    close_handle(thread);
    close_handle(proc);
    close_handle(job);
#else
    if (pid > 0) {
      kill_group(pid);
      int st = 0;
      while (::waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
      if (WIFEXITED(st))        exit_code_value = WEXITSTATUS(st);
      else if (WIFSIGNALED(st)) exit_code_value = 128 + WTERMSIG(st);
      pid = -1;
    }
    if (out_thread.joinable()) out_thread.join();
    if (err_thread.joinable()) err_thread.join();
    close_fd(out_fd);
    close_fd(err_fd);
#endif
    pid_value = 0;
    LOG_DEBUG("proc: child: killed, exit={}", exit_code_value);
  }

  bool wait_for_exit(unsigned ms) {
    if (!alive.load()) return true;

#if defined(_WIN32)
    if (proc == nullptr) return true;
    const DWORD waited =
        WaitForSingleObject(proc, static_cast<DWORD>(ms));
    if (waited == WAIT_OBJECT_0) {
      DWORD code = 0;
      GetExitCodeProcess(proc, &code);
      exit_code_value = static_cast<int>(code);
      alive.store(false);
      return true;
    }
    return false;
#else
    if (pid <= 0) return true;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(ms);
    for (;;) {
      int st = 0;
      const pid_t done = ::waitpid(pid, &st, WNOHANG);
      if (done == pid) {
        if (WIFEXITED(st))        exit_code_value = WEXITSTATUS(st);
        else if (WIFSIGNALED(st)) exit_code_value = 128 + WTERMSIG(st);
        pid = -1;
        alive.store(false);
        return true;
      }
      if (done < 0 && errno != EINTR) {
        alive.store(false);
        return true;
      }
      if (ms == 0 || std::chrono::steady_clock::now() >= deadline) {
        return false;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
#endif
  }
};

child::child() : impl_(new impl()) {}
child::~child() { delete impl_; impl_ = nullptr; }

launch_status child::start(const std::string& program,
                           const std::vector<std::string>& args,
                           const run_options& options) {
  return impl_->start(program, args, options);
}

bool          child::running()        const { return impl_->alive.load(); }
std::uint64_t child::pid()            const { return impl_->pid_value; }
void          child::kill()                 { impl_->kill(); }
bool          child::wait_for_exit(unsigned ms) { return impl_->wait_for_exit(ms); }
int           child::exit_code()      const { return impl_->exit_code_value; }

std::string child::std_out() const {
  std::lock_guard<std::mutex> lock(impl_->mtx);
  return impl_->out_buf;
}

std::string child::std_err() const {
  std::lock_guard<std::mutex> lock(impl_->mtx);
  return impl_->err_buf;
}

} 