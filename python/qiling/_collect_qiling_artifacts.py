"""Fetch Qiling results (report zips, logs) from the analysis VM.

VM layout (per-sample directories):
  <app_dir>/samples/<stem>/<name>.exe            uploaded sample
  <app_dir>/samples/<stem>/<stem>_qiling_out.zip analysis results
  <app_dir>/qilin-service.log                    service-wide log

Artifacts are pulled onto this machine under
config/systemd/qilin-service/artifacts/ with the same structure:
  artifacts/<stem>/<stem>_qiling_out.zip
  artifacts/qilin-service.log
"""
import pathlib

DEFAULT_APP_DIR = "/home/qilin/.config/systemd/qilin-service"

# This script lives in python/qiling/, so the repo root is two levels above its
# own directory (python/qiling -> python -> repo), i.e. parents[2] of the file.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ARTIFACTS_DIR = REPO_ROOT / "config" / "systemd" / "qilin-service" / "artifacts"


def collect_artifacts(ssh_client, remote_paths, local_dir=ARTIFACTS_DIR,
                      rel_root=None):
    """SFTP-get every remote path into local_dir, keeping rel_root structure.

    rel_root: remote prefix stripped from each path to build the local
    subdirectory (e.g. app_dir -> samples/<stem>/file lands in
    local_dir/samples/<stem>/file). With rel_root=None files land flat.
    Returns a list of dicts: {"remote", "local", "ok", "detail"}.
    """
    if not ssh_client:
        raise ValueError("ssh_client is required")
    local = pathlib.Path(local_dir)
    try:
        sftp = ssh_client.open_sftp()
    except Exception as e:
        raise RuntimeError("cannot open sftp: {}".format(e)) from e
    results = []
    prefix = rel_root.rstrip("/") + "/" if rel_root else None
    try:
        for remote in remote_paths:
            entry = {"remote": remote, "local": None, "ok": False, "detail": ""}
            try:
                if prefix and remote.startswith(prefix):
                    target = local / pathlib.PurePosixPath(remote[len(prefix):])
                else:
                    target = local / pathlib.PurePosixPath(remote).name
                target.parent.mkdir(parents=True, exist_ok=True)
                sftp.get(remote, str(target))
                entry.update(local=str(target), ok=True,
                             detail="{} bytes".format(target.stat().st_size))
            except Exception as e:
                entry["detail"] = str(e)
            results.append(entry)
    finally:
        sftp.close()
    return results


def collect_service_artifacts(ssh_client, app_dir=DEFAULT_APP_DIR,
                              local_dir=ARTIFACTS_DIR):
    """Collect per-sample zips/logs plus the service-wide log.

    Walks <app_dir>/samples/<stem>/ for *_qiling_out.zip / *.log and also
    picks up any flat artifacts left in app_dir (older runs).
    """
    base = app_dir.rstrip("/")
    remote = []
    try:
        sftp = ssh_client.open_sftp()
    except Exception as e:
        raise RuntimeError("cannot open sftp: {}".format(e)) from e
    try:
        try:
            top = sorted(sftp.listdir(base))
        except Exception as e:
            raise RuntimeError("cannot list {}: {}".format(base, e)) from e
        for name in top:
            if name.endswith("_qiling_out.zip") or name.endswith(".log"):
                remote.append("{}/{}".format(base, name))
        try:
            stems = sorted(sftp.listdir(base + "/samples"))
        except Exception:
            stems = []
        for stem in stems:
            try:
                names = sorted(sftp.listdir(base + "/samples/" + stem))
            except Exception:
                continue
            for name in names:
                if name.endswith("_qiling_out.zip") or name.endswith(".log"):
                    remote.append("{}/samples/{}/{}".format(base, stem, name))
    finally:
        sftp.close()
    if not remote:
        return []
    return collect_artifacts(ssh_client, remote, local_dir, rel_root=base)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(pathlib.Path(__file__).parent))
    from _configure_quiling import check_ssh_connectivity_normal_user, \
        recover_host_information

    info = recover_host_information()
    if not info:
        sys.exit("cannot read vm_info.json")
    ssh = check_ssh_connectivity_normal_user(info)
    if not ssh:
        sys.exit("ssh failed")
    try:
        app_dir = info.get("APP_DIR") or DEFAULT_APP_DIR
        rows = collect_service_artifacts(ssh, app_dir=app_dir)
        if not rows:
            print("[!] no *_qiling_out.zip / *.log under {}".format(app_dir))
        for row in rows:
            mark = "OK " if row["ok"] else "ERR"
            print("[{}] {} <- {} ({})".format(mark, row["local"], row["remote"],
                                              row["detail"]))
    finally:
        ssh.close()
