import json
import pathlib
import subprocess

# Pick a function offset from the existing r2 artifact.
p = pathlib.Path("exports/radare2/a_radare2.json")
data = json.loads(p.read_text(encoding="utf-8"))
fns = [f for f in data.get("functions", []) if f.get("offset") and f.get("size")]
if not fns:
    print("no functions in artifact")
    raise SystemExit(1)
off = fns[0]["offset"]
print("offset:", hex(off), "name:", fns[0].get("name"))

# Reproduce the runner's exact invocation (no -A to keep it fast; add -A if needed).
cmd = [
    "wsl", "r2", "-q",
    "-e", "scr.color=0", "-e", "scr.utf8=0",
    "-e", "scr.interactive=false", "-e", "scr.prompt=false",
    "-A",
    "-c", f"pdfj @ {hex(off)}",
    "-c", "q",
    "/mnt/c/Users/The4thReich/Desktop/IAProject/a.exe",
]
print("running:", " ".join(cmd[:8]), "...")
try:
    r = subprocess.run(cmd, capture_output=True, timeout=180)
except Exception as exc:
    print("launch error:", exc)
    raise SystemExit(1)

print("exit:", r.returncode)
out = r.stdout.decode("utf-8", "replace")
err = r.stderr.decode("utf-8", "replace")
print("stdout bytes:", len(out))
print("stderr bytes:", len(err))
print("stdout[:500]:", repr(out[:500]))
print("stderr[:500]:", repr(err[:500]))