import pathlib
import re

log = pathlib.Path("logs/trace.txt")
if not log.is_file():
    print("no trace log")
    raise SystemExit(1)

text = log.read_text(encoding="utf-8", errors="replace")
# Grab lines mentioning the r2 run_tool call and its result, plus the asm step.
pat = re.compile(
    r"(run_tool: exit=.*|r2: run_tool: '.*pdfj.*|dump_function_assembly.*|"
    r"no parseable.*|list_functions.*|local_api.*error.*)",
)
hits = [ln for ln in text.splitlines() if pat.search(ln)]
for ln in hits[-25:]:
    print(ln[:420])