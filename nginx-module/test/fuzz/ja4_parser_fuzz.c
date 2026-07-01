/*
 * ja4_parser_fuzz.c — libFuzzer harness for ja4_parse_client_hello().
 *
 * License: Apache 2.0 (clean-room implementation from JA4 specification)
 *
 * Purpose: feed malformed / boundary TLS ClientHello bytes into the pure-C
 *          parser to catch heap corruption, OOB read, and NULL deref.  The
 *          parser is reachable from every TLS request that hits an
 *          unmask-enabled nginx, so a crash here is a remote DoS.
 *
 * Why a separate harness: the in-tree src/ja4_parser_fuzz.c is a portable
 *          xorshift32 sweep that runs anywhere gcc is available (= CI default).
 *          This file is the libFuzzer/AFL++ coverage-guided variant which
 *          requires clang or AFL++ and produces deeper inputs.  Both share
 *          ja4_parser.c with no nginx dependency, so the fuzz target builds
 *          without linking against the nginx tree.
 *
 * Build (libFuzzer + ASan + UBSan):
 *   clang -g -O1 \
 *       -fsanitize=fuzzer,address,undefined \
 *       -fno-sanitize-recover=all \
 *       -I ../../src \
 *       ../../src/ja4_parser.c ja4_parser_fuzz.c \
 *       -o ja4_parser_fuzz
 *
 * Run (60 s quick sweep with seed corpus):
 *   ./ja4_parser_fuzz -max_total_time=60 corpus/
 *
 * Reproduce a crash:
 *   ./ja4_parser_fuzz crash-<sha1>     # libFuzzer drops the file in CWD
 *
 * See test/fuzz/README.md for the AFL++ alternative and CI integration.
 */

#include "ja4_parser.h"

#include <stddef.h>
#include <stdint.h>

/*
 * LLVMFuzzerTestOneInput: libFuzzer entry point.  Called repeatedly with
 * mutated inputs.  Must return 0 and must not crash on any input.
 *
 * Invariants asserted via sanitizers:
 *   - no read past `data + size`            (ASan)
 *   - no NULL deref                          (ASan)
 *   - no signed overflow / shift UB          (UBSan)
 *   - no use of uninitialized memory in out  (caller contract: only trust
 *                                             `out` when return value == 0;
 *                                             we still read every field on
 *                                             success so MSan-like checks
 *                                             would flag any miss).
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ja4_parsed_t out;
    int rc;

    rc = ja4_parse_client_hello(data, size, &out);
    if (rc != 0) {
        return 0;
    }

    /*
     * Touch every populated field so that sanitizers see use of the bytes
     * the parser wrote.  Without this, the compiler may dead-code the
     * memset / writes and ASan/MSan diagnostics get muddied.  The volatile
     * sink prevents the loop from being optimised away.
     */
    volatile unsigned int sink = 0;
    sink ^= out.legacy_version;
    sink ^= out.supported_versions_max;
    sink ^= (unsigned int)out.sni_present_domain;
    sink ^= (unsigned int)out.alpn_first;
    sink ^= (unsigned int)out.alpn_last;
    sink ^= (unsigned int)out.has_sig_algs;

    if (out.ncipher < 0 || out.ncipher > JA4_MAX_CIPHERS) {
        __builtin_trap();  /* parser contract violation */
    }
    for (int i = 0; i < out.ncipher; i++) {
        sink ^= out.ciphers[i];
    }

    if (out.nexts < 0 || out.nexts > JA4_MAX_EXTENSIONS) {
        __builtin_trap();
    }
    for (int i = 0; i < out.nexts; i++) {
        sink ^= out.extensions[i];
    }

    if (out.nsig_algs < 0 || out.nsig_algs > JA4_MAX_SIG_ALGS) {
        __builtin_trap();
    }
    for (int i = 0; i < out.nsig_algs; i++) {
        sink ^= out.sig_algs[i];
    }

    (void)sink;
    return 0;
}
