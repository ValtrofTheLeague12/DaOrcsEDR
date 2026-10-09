#include "pipeline.hpp"

#include <cstdlib>
#include <iomanip>
#include <ios>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "console.hpp"
#include "logging.hpp"
#include "process_runner.hpp"
#include "secret_store.hpp"

namespace pipeline {

// ---------------------------------------------------------------------------
// Phase 20: CTI threat-intel pipeline
// ---------------------------------------------------------------------------
void run_cti(context& ctx) {
  const auto started = report_clock::now();
  phase(ctx, true, "CTI threat intel");

  // Keys come from the environment or from Bitwarden (no header configuration
  // / no CLI flags); providers without a key are skipped and listed in the
  // report warnings.

  // Allow the smoke / CI run (no keys, no network) to skip the internet
  // lookups without hanging.
  const bool cti_skip = [] {
    const char* v = std::getenv("CTI_SKIP");
    return v && (std::string(v) == "1" || std::string(v) == "true");
  }();

  // ---- Bitwarden credential reconciliation ---------------------------------
  // Pull the CTI keys from a running `bw serve` so they never rest on disk.
  // Opt-in via CTI_BW_KEYS: a comma-separated roster of "Item=ENV_TARGET"
  // pairs; a bare "Item" only checks that the vault holds it. The legacy
  // CTI_KEY_NAME + CTI_KEY_TARGET pair keeps working and is appended to the
  // roster. This pass is loopback-only, so it also runs when CTI_SKIP is
  // set: the skip flag is about not touching the internet, not about the
  // vault. Values live in this scope only - never logged, never placed in a
  // structure that reaches the exporter, unset when the phase ends.
  std::vector<std::string> vault_targets;
  {
    std::vector<secret_store::item_request_t> wanted;
    const char* bw_keys = std::getenv("CTI_BW_KEYS");
    if (bw_keys != nullptr && *bw_keys != '\0') {
      std::string parse_error;
      if (!parse_vault_key_list(bw_keys, wanted, parse_error)) {
        print_warn("CTI_BW_KEYS ignored: " + parse_error);
        wanted.clear();
      }
    }
    const char* key_name   = std::getenv("CTI_KEY_NAME");
    const char* key_target = std::getenv("CTI_KEY_TARGET");
    if (key_name != nullptr && *key_name != '\0' &&
        key_target != nullptr && *key_target != '\0') {
      wanted.push_back({key_name, key_target});
    }

    if (!wanted.empty()) {
      const char* base_env = std::getenv("CTI_BW_SERVE_URL");
      const std::string base = (base_env != nullptr && *base_env != '\0')
                                   ? base_env : "http://127.0.0.1:8087";

      print_section("CTI credentials (Bitwarden)");
      print_kv("Source", "`bw serve` " + base + " (in-memory, never on disk)");
      print_kv("Requested keys", std::to_string(wanted.size()));

      secret_store::batch_result_t vault =
          secret_store::fetch_many_from_bw_serve(wanted, base);

      if (!vault.listing_ok) {
        print_warn("Bitwarden lookup failed: " + vault.error);
      } else {
        print_kv("Vault items visible", std::to_string(vault.vault_items));
      }

      std::size_t present = 0, missing = 0, unusable = 0;
      for (secret_store::item_result_t& item : vault.items) {
        std::ostringstream line;
        line << std::left << std::setw(26) << item.name;
        if (!item.target.empty()) {
          line << " -> " << std::left << std::setw(22) << item.target;
        } else {
          line << " (existence check)";
        }

        if (!vault.listing_ok) {
          // One reason was already reported above; do not repeat it per key.
          line << "  not checked (Bitwarden unavailable)";
          print_bullet(line.str(), console::red);
          continue;
        }

        switch (item.state) {
          case secret_store::item_state::present: {
            ++present;
            if (item.value_loaded && !item.target.empty()) {
              // Keep the key out of every child process we spawn. The CTI
              // phase runs before the export/dashboard phases, which launch
              // wsl.exe, capa and the Python generator - none of them need
              // this variable, and all of them would otherwise inherit it.
              proc::protect_env_var(item.target);
#ifdef _WIN32
              const bool applied = _putenv_s(item.target.c_str(), item.value.c_str()) == 0;
#else
              const bool applied =
                  ::setenv(item.target.c_str(), item.value.c_str(), 1) == 0;
#endif
              // Drop the secret from memory once it is in the environment.
              item.value.assign(item.value.size(), '\0');
              item.value.clear();
              if (applied) {
                vault_targets.push_back(item.target);
                line << "  in vault -> applied for this run only";
                print_bullet(line.str(), console::green);
              } else {
                line << "  in vault, but could not set " << item.target;
                print_bullet(line.str(), console::red);
              }
            } else {
              line << "  present in vault";
              print_bullet(line.str(), console::green);
            }
            break;
          }
          case secret_store::item_state::missing:
            ++missing;
            line << "  NOT in the vault";
            print_bullet(line.str(), console::yellow);
            break;
          case secret_store::item_state::ambiguous:
            ++unusable;
            line << "  unusable: " << item.error;
            print_bullet(line.str(), console::red);
            break;
          case secret_store::item_state::unusable:
            ++unusable;
            line << "  in vault but unusable: " << item.error;
            print_bullet(line.str(), console::red);
            break;
        }
      }

      if (vault.listing_ok) {
        std::ostringstream summary;
        summary << "Bitwarden: " << present << " of " << vault.items.size()
                << " key(s) present";
        if (missing != 0)  summary << ", " << missing << " missing";
        if (unusable != 0) summary << ", " << unusable << " unusable";
        if (missing == 0 && unusable == 0) console::success(summary.str());
        else                               print_warn(summary.str());
        if (missing != 0) {
          print_bullet("add the missing entries as Bitwarden login items "
                       "(password = API key) and re-run", console::grey);
        }
      }
    }
  }

  if (cti_skip) {
    console::info("CTI phase skipped (CTI_SKIP=1) — internet lookups disabled");
  } else {

    // Endpoint / key overrides from a JSON file (CTI_CONFIG). cti::config has always
    // documented this overlay, but nothing ever read it, so the pipeline could only be
    // pointed at a proxy or a test server by editing the endpoints in the source.
    cti::config cti_cfg = cti::config::from_environment();
    if (const char* overlay = std::getenv("CTI_CONFIG"); overlay != nullptr && *overlay != '\0') {
      std::string overlay_error;
      if (!cti_cfg.merge_json_file(overlay, overlay_error))
        print_warn("CTI_CONFIG ignored: " + overlay_error);
    }
    cti::pipeline pipe(std::move(cti_cfg));
    if (!pipe.network_available()) {
      console::info("No internet connection found — skipping CTI phase.");
    } else {

    // Seed the pipeline from the artifacts already extracted in this run.
    cti::collect_from_ioc(pipe, ctx.ioc_results);
    cti::collect_from_extraction(pipe, ctx.full);

    // The file hasher exposes a single unified hash member; feed whichever
    // hash the hasher produced (md5/sha1 are left empty and ignored).
    cti::add_file_hashes(pipe, ctx.file_hash.hash, "", "");

    // Progress: one line per completed (source, artifact) query. The source
    // name is the provider that answered, which is what makes the trace
    // readable - a bare round/task counter says nothing about where the
    // intelligence came from. A header is printed whenever the pipeline
    // moves to the next round (the callback fires per task, possibly from
    // several worker threads at once, hence the lock).
    std::mutex cti_progress_mtx;
    int        cti_progress_round = -1;

    ctx.cti_report = pipe.run([&](const cti::progress_info& info) {
      std::lock_guard<std::mutex> lock(cti_progress_mtx);

      if (info.round != cti_progress_round) {
        cti_progress_round = info.round;
        std::ostringstream head;
        head << "cti round " << (info.round + 1) << ": "
             << (info.round == 0 ? "artifacts collected in this scan"
                                 : "artifacts derived from earlier answers")
             << " (" << info.total << " query task(s))";
        console::info(head.str());
      }

      std::ostringstream os;
      os << std::left << std::setw(18) << info.provider
         << ' ' << std::left << std::setw(46) << info.artifact
         << " [" << info.done << '/' << info.total << ']';
      console::info(os.str());
    });

    std::vector<const cti::enrichment*> cti_ips;
    for (const cti::enrichment& item : ctx.cti_report.items) {
      if (item.art.type == cti::artifact_type::ip) cti_ips.push_back(&item);
    }
    if (!cti_ips.empty()) {
      print_section("CTI IP network information");
      for (const cti::enrichment* item : cti_ips) {
        print_ip_network_info(item->art.value, item->net);
      }
    }

    if (ctx.cti_report.items.empty() && ctx.cti_report.warnings.empty()) {
      console::info("CTI pipeline produced no artifacts (no keys / no results for this sample)");
    } else {
      cti::print_summary(ctx.cti_report, std::cout);
    }

    const bool cti_ok = !ctx.cti_report.items.empty();
    if (cti_ok) console::success("CTI: " + std::to_string(ctx.cti_report.items.size()) +
                                 " artifact(s), " + std::to_string(ctx.cti_report.counts_by_verdict.size()) +
                                 " verdict categories");
    else        console::info("CTI: no artifacts collected for this sample");
    }
  }

  // Drop every vault-sourced credential from the process environment as soon
  // as the phase is over, so none of them can leak into a later phase (or a
  // child process) that happens to read it.
  for (const std::string& target : vault_targets) {
#ifdef _WIN32
    _putenv_s(target.c_str(), "");
#else
    ::unsetenv(target.c_str());
#endif
  }
  vault_targets.clear();

  print_duration(elapsed_ms(started));
}

}  // namespace pipeline
