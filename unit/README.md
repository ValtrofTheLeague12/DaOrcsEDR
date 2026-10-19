# unit/

Unit tests. Two suites, one per language.

```
unit/
  python/     pytest, 58 tests   - panel config, malapi_pipeline, yara_gen, utils
  c++/        no framework, 27  - app_paths, resume, default_pipeline
```

## What belongs here, and what does not

The distinction is what the test needs, not how big it is.

| | unit/ | tests/ |
|---|---|---|
| needs | nothing but the code under test | the built analyzer, a sample, services, network |
| speed | under a second | seconds to minutes |
| failure means | the code is wrong | the code or the environment is wrong |

A test that shells out to `static_analyzer.exe` and reads `run_summary.json`
belongs in `tests/`. A test that reads the phase catalog *through* that binary
sits in between, and it lives here because it is fast and needs no sample — see
`test_default_pipeline` below.

`tests/` is not superseded by this directory. It covers the black-box behaviour;
this covers the decisions.

## Running

```
python\.venv\Scripts\python.exe -m pytest unit\python -q

cmake -S . -B build-ucrt
cmake --build build-ucrt --target unit_tests      # build all three
cmake --build build-ucrt --target run_test_resume # build and run one
```

The C++ tests are deliberately **not** in `all`. A test target that builds by
default is a test target nobody runs.

Exit code is 0 for pass, 1 for failure — so a CI step is one command and a check.

## Output

```
  ...  the_harness_itself_runs
  ok    the_harness_itself_runs
  ...
  9 passed, 0 failed
```

`...` before a name means it is *running*. That line is flushed immediately, so a
suite that hangs says which test is hanging instead of going quiet.

On a fault the harness prints the crash banner and names the test that died:

```
[unit] crashed with signal 11 during: root_is_keyed_on_the_app_basename
```

Both banners are the analyzer's own `banner.cpp` — `daorcs.logo` on start, the
red `crash.logo` on a fault — rather than copies, so "where does logos/ live"
stays answered in one place. `unit/c++/console_stub.cpp` supplies the single
`console::paint` that banner needs; linking the real `console.cpp` would drag in
logging → redact → file_hasher, and a path-resolution test should not fail to
build because a logging sink changed.

## The harness

`unit/c++/test_main.hpp` is the whole of it — a registry, four macros, an exit
code. No gtest, no dependency change, no build-system convention to learn:

```cpp
TEST(name) { ... }          // registers itself
CHECK(cond)                // fails with the expression text
CHECK_EQ(a, b)             // fails with both values
```

A failing assertion prints the file, the line, the expression, and both sides,
then abandons that case and carries on — so one broken invariant produces one
paragraph rather than six.

## What these found

Not hypothetical; these are what the first run reported.

- **`begin()` writes no checkpoint.** The resume file appears on the first
  completed phase, not at run start. That is correct — a run that dies before
  finishing anything has nothing to resume from — and it is not obvious, so
  `test_resume` pins it.
- **`completed` is a list, not a set.** A phase selected twice appears twice.
  Harmless for the skip-set it feeds, but a reader would assume otherwise.
- **`setting()` ignored `KEY = value`.** A `.env` written with spaces around
  the `=` fell through to the default silently. Now split on the first `=`
  rather than matching a `name=` prefix, which also stops `SA_API_PORT_EXTRA`
  from satisfying a request for `SA_API_PORT`.
- **The rule inventory crashed on a rules directory outside the repo.** It is a
  setting (`YARA_RULES_DIR`); an inventory helper is the wrong place to raise.

## Known gaps

Honest about what is *not* covered, because an empty spot is worse than a slow
one:

- **`pipeline_planner.cpp` has no unit tests** — the largest untested surface
  in the project. It pulls in the extractor, radare2 and ML headers, so a test
  binary for it is a real piece of work rather than a link line. Its behaviour
  is covered from outside by `test_default_pipeline` and by `tests/`.
- **No C++ test for `redact`.** Secret redaction is security-critical and
  untested; `redact.cpp` needs `file_hasher.cpp`, which needs the console and
  logging chain.
- **The `IA_APPDATA_DIR` override** is untested here, because the resolver
  caches into a function-local static and an in-process test cannot observe a
  change. It needs a subprocess test, which belongs in `tests/`.