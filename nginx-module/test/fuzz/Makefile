# Makefile for nginx-module/test/fuzz/ — libFuzzer harness build.
#
# License: Apache 2.0 (clean-room implementation from JA4 specification)
#
# Targets:
#   make build          build ja4_parser_fuzz with libFuzzer + ASan + UBSan
#   make fuzz           60 s quick run (= CI default)
#   make fuzz-long      24 h background run (= soak; logs to fuzz-long.log)
#   make repro CRASH=f  replay a single crash file
#   make clean          remove the binary, crash-*, leak-*, oom-*, slow-*
#                       artefacts.  Does not touch corpus/ or new-corpus/.
#
# Requires: clang (= ships with libFuzzer; gcc has no libFuzzer support).
# On dev2 / RHEL 9: `dnf install clang` (= 17.0.6 from AppStream).

SRC_DIR  ?= ../../src
HARNESS  := ja4_parser_fuzz.c
PARSER   := $(SRC_DIR)/ja4_parser.c
BIN      := ja4_parser_fuzz

# NOTE: assigned with `=`, not `?=`.  Make pre-defines CC=cc, so `?=` would
# resolve to gcc and -fsanitize=fuzzer would be rejected.  Override on the
# command line if a different clang is desired: `make CC=clang-17 fuzz`.
CC        = clang
CFLAGS    ?= -g -O1 -Wall -Wextra
FUZZ_FLAGS := -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all
INCLUDES   := -I$(SRC_DIR)

# Time and memory caps for libFuzzer.  Adjust per environment.
FUZZ_TIME_QUICK ?= 60
FUZZ_TIME_LONG  ?= 86400
RSS_LIMIT_MB    ?= 2048
TIMEOUT_SEC     ?= 25
MAX_LEN         ?= 65600   # = largest seed (07-large-ext-body.bin) + slack

# corpus/ = static seeds checked into git; new-corpus/ = libFuzzer's running
# coverage corpus (= gitignored).  Both directories are passed on the
# command line; libFuzzer writes new inputs into the first one.
SEED_DIR := corpus
WORK_DIR := new-corpus

.PHONY: build fuzz fuzz-long fuzz-cont repro clean check-clang

build: check-clang $(BIN)

check-clang:
	@command -v $(CC) >/dev/null 2>&1 || { \
		echo "ERROR: $(CC) not found in PATH"; \
		echo "  install: dnf install clang  (RHEL/Rocky)"; \
		echo "           apt install clang  (Debian/Ubuntu)"; \
		echo "           apk add clang19 compiler-rt  (Alpine 3.19+)"; \
		exit 1; \
	}

$(BIN): $(HARNESS) $(PARSER) $(SRC_DIR)/ja4_parser.h
	$(CC) $(CFLAGS) $(FUZZ_FLAGS) $(INCLUDES) \
		$(PARSER) $(HARNESS) -o $(BIN)

$(WORK_DIR):
	mkdir -p $(WORK_DIR)

# fuzz — 60 s quick run.  Non-zero exit iff libFuzzer found a crash / leak.
fuzz: build $(WORK_DIR)
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:halt_on_error=1 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	./$(BIN) \
		-max_total_time=$(FUZZ_TIME_QUICK) \
		-rss_limit_mb=$(RSS_LIMIT_MB) \
		-timeout=$(TIMEOUT_SEC) \
		-max_len=$(MAX_LEN) \
		-print_final_stats=1 \
		$(WORK_DIR) $(SEED_DIR)

# fuzz-long — 24 h run.  Foreground so the calling shell stays responsible
# for backgrounding (= run with `nohup make fuzz-long &` or under tmux).
# Stats are printed every 60 s and at the end.
fuzz-long: build $(WORK_DIR)
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:halt_on_error=1 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	./$(BIN) \
		-max_total_time=$(FUZZ_TIME_LONG) \
		-rss_limit_mb=$(RSS_LIMIT_MB) \
		-timeout=$(TIMEOUT_SEC) \
		-max_len=$(MAX_LEN) \
		-print_pcs=0 \
		-print_final_stats=1 \
		$(WORK_DIR) $(SEED_DIR)

# fuzz-cont — continue from the existing $(WORK_DIR) without a time cap.
# Useful for interactive babysitting.  Ctrl-C to stop.
fuzz-cont: build $(WORK_DIR)
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:halt_on_error=1 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	./$(BIN) \
		-rss_limit_mb=$(RSS_LIMIT_MB) \
		-timeout=$(TIMEOUT_SEC) \
		-max_len=$(MAX_LEN) \
		-print_final_stats=1 \
		$(WORK_DIR) $(SEED_DIR)

# repro CRASH=path — replay a single input with sanitizers fully armed.
# Exit code reflects the parser behaviour (0 = clean, non-zero = crash).
repro: build
	@if [ -z "$(CRASH)" ]; then echo "usage: make repro CRASH=<file>"; exit 2; fi
	ASAN_OPTIONS=abort_on_error=0:halt_on_error=1 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	./$(BIN) $(CRASH)

clean:
	rm -f $(BIN)
	rm -f crash-* leak-* oom-* slow-* timeout-*
	rm -f fuzz-*.log
