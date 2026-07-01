# `ja4_parse_client_hello` fuzz harness

Coverage-guided fuzzer for `nginx-module/src/ja4_parser.c`, the pure-C
TLS ClientHello parser that runs inside every TLS request handled by an
unmask-enabled nginx.

A crash here is a remote DoS (= worker process abort) on any host that
ships the unmask plugin, so the parser has a near-zero crash budget.
The existing portable random sweep at `src/ja4_parser_fuzz.c` is the
default CI gate; this directory adds the deeper, coverage-guided
variant used before tagging a release.

## Prerequisites

- `clang` (= libFuzzer ships with clang; gcc cannot build the harness).
  - RHEL/Rocky 9: `sudo dnf install clang`
  - Debian/Ubuntu: `sudo apt install clang`
  - Alpine 3.19+: `sudo apk add clang19 compiler-rt`
- `make`, `python3` (= corpus regeneration only).

## Quick run (= 60 s, CI default)

```sh
cd nginx-module/test/fuzz
./run-fuzz.sh
```

`./run-fuzz.sh <seconds>` overrides the time cap.  The script wraps
`make fuzz` and forwards the libFuzzer exit code, so any crash / leak /
OOM surfaces as a non-zero exit.

## 24 h soak

```sh
cd nginx-module/test/fuzz
nohup ./run-fuzz.sh long > fuzz-long.log 2>&1 &
disown
```

Or under tmux:

```sh
tmux new -s ja4-fuzz './run-fuzz.sh long 2>&1 | tee fuzz-long.log'
```

The harness keeps the libFuzzer working corpus in `./new-corpus/` so
subsequent runs resume from the accumulated coverage frontier.  Wipe
that directory to restart from scratch.

## Reproducing a crash

libFuzzer drops crash inputs as `crash-<sha1>` in the current working
directory.  Replay with:

```sh
make repro CRASH=crash-1234abcd...
```

The repro target runs the harness against the single input with ASan +
UBSan armed and `halt_on_error=1`, so the failure mode and stack trace
print verbatim.

If the crash needs a smaller witness:

```sh
./ja4_parser_fuzz -minimize_crash=1 -runs=100000 crash-1234abcd...
```

## Build flags

`Makefile` builds the harness with:

```
clang -g -O1 -Wall -Wextra \
    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
    -I ../../src \
    ../../src/ja4_parser.c ja4_parser_fuzz.c -o ja4_parser_fuzz
```

- `-fsanitize=fuzzer` injects the libFuzzer driver (= replaces `main`).
- `-fsanitize=address` catches OOB reads, double-free, use-after-free.
- `-fsanitize=undefined` catches signed overflow, shift UB, alignment.
- `-fno-sanitize-recover=all` makes any sanitizer hit abort immediately
  (= libFuzzer treats it as a crash and saves the input).

`MSan` is intentionally not enabled: it requires a full sanitized
rebuild of every dependency, and the parser has no dependency outside
libc (= AddressSanitizer's uninitialized-read detection plus the
explicit `__builtin_trap()` on out-of-range struct fields are
sufficient).

## Seed corpus

`corpus/` holds 10 hand-crafted ClientHello messages assembled by
`corpus/gen.py` from the wire format described in RFC 5246 §7.4.1.2 and
RFC 8446 §4.1.2.  No external packet dump or BSL-licensed reference
implementation is consulted (= clean-room).

To refresh after editing:

```sh
cd corpus
python3 gen.py
```

The seeds cover:

| File                            | Shape                                                    |
|---------------------------------|----------------------------------------------------------|
| `01-tls10-no-ext.bin`           | TLS 1.0 ClientHello with no extensions block.            |
| `02-tls12-sni-alpn.bin`         | TLS 1.2 with SNI, ALPN h2/http1.1, sig_algs.             |
| `03-tls13-grease.bin`           | TLS 1.3 with GREASE entries in ciphers and extensions.   |
| `04-cipher-overflow.bin`        | 300 ciphers; exercises the cipher-cap truncation branch. |
| `05-empty-ext-block.bin`        | Well-formed empty extensions block (= length 0).         |
| `06-tls13-mbox-compat.bin`      | TLS 1.3 with a 32-byte session_id (= middlebox mode).    |
| `07-large-ext-body.bin`         | One extension with a 65530-byte body (= near u16 max).   |
| `08-alpn-single-char.bin`       | ALPN proto of length 1; first/last char coincide.        |
| `09-truncated-after-ciphers.bin`| Malformed: truncated before compression_methods.         |
| `10-tiny.bin`                   | 1-byte input (= HandshakeType only).                     |

## AFL++ alternative

The harness compiles unchanged under `afl-clang-lto-fast` or `afl-gcc-fast`
once libFuzzer's `LLVMFuzzerTestOneInput` is wrapped:

```sh
# Build (AFL++ persistent mode with libFuzzer-style entry).
afl-clang-lto-fast -O1 -g \
    -I ../../src \
    ../../src/ja4_parser.c ja4_parser_fuzz.c \
    /path/to/AFLplusplus/utils/aflpp_driver/aflpp_driver.c \
    -o ja4_parser_afl

# Run.
mkdir -p afl-out
AFL_AUTORESUME=1 afl-fuzz -i corpus -o afl-out -- ./ja4_parser_afl
```

Crashes land in `afl-out/default/crashes/`; replay with the same
`make repro CRASH=...` command (= the harness binary itself accepts a
positional input file).

AFL++ is recommended for runs over a week or for distributed fuzzing
(= `afl-fuzz -M main -S worker1 ... worker N`); libFuzzer is the
better fit for the in-CI 60 s gate because of its low setup cost.

## Known limitations

- The harness exercises **only** `ja4_parse_client_hello`.  The downstream
  JA4 string construction inside `ngx_http_unmask_module.c` is reached
  via a different code path and is **not** fuzzed here.  It uses fixed
  output buffers and is covered by `make test-plugin-parser` plus the
  e2e tests; if that code is modified, add a separate harness.
- Sanitizers slow the parser ~5-10x; perf numbers from this harness are
  not representative of production throughput.
- `-max_len=65600` is sized for the largest seed.  Inputs bigger than
  that are uncommon (= ClientHello messages over 16 KiB are already
  rejected by nginx before they reach the parser), but if a regression
  reproduces only with a larger input, raise the cap.
- libFuzzer's leak detection requires `detect_leaks=1` in
  `ASAN_OPTIONS`; this is set by the Makefile.  Disable with
  `ASAN_OPTIONS=detect_leaks=0` if false positives appear on a
  container without `/proc/self/maps`.

## CI integration

Suggested CI step (= GitHub Actions example, runs alongside
`make test-plugin-parser`):

```yaml
- name: ja4 parser fuzz (60 s gate)
  run: |
    sudo apt install -y clang
    make -C nginx-module/test/fuzz fuzz
```

The 24 h soak is a release-gate, not a per-PR check; run it manually
before tagging.
