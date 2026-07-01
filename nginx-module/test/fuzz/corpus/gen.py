#!/usr/bin/env python3
# gen.py — regenerate the seed corpus for ja4_parser_fuzz.
#
# License: Apache 2.0 (clean-room implementation from JA4 specification)
#
# Each file is a raw TLS handshake message starting at the HandshakeType
# byte (= what ja4_parse_client_hello expects).  Bytes are assembled from
# RFC 5246 / RFC 8446 wire-format only; no Wireshark / packet dump is
# embedded.  Re-run after editing to refresh the .bin files in this
# directory:
#
#   python3 gen.py
#
# libFuzzer ignores the .py file because it is not a valid input
# (parser rejects msg_type != 1), so leaving it next to the corpus is safe.

from __future__ import annotations

import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def build_client_hello(legacy_version: int,
                       ciphers: list[int],
                       compression_methods: list[int],
                       extensions: list[tuple[int, bytes]] | None,
                       random_pad: int = 0xCC,
                       session_id: bytes = b"") -> bytes:
    """
    Return a ClientHello handshake message starting at HandshakeType (=1).

    Layout (RFC 8446 §4.1.2 with TLS 1.2 compatibility):
        struct {
            HandshakeType msg_type;       uint8  = 1
            uint24        length;
            ProtocolVersion legacy_version; uint16
            Random          random;         32 bytes
            opaque legacy_session_id<0..32>;
            CipherSuite cipher_suites<2..2^16-2>;
            opaque legacy_compression_methods<1..2^8-1>;
            Extension extensions<8..2^16-1>;     // optional in TLS 1.0
        }
    """
    body = bytearray()
    body += struct.pack(">H", legacy_version)         # legacy_version
    body += bytes([random_pad] * 32)                  # random
    assert len(session_id) <= 32
    body += bytes([len(session_id)]) + session_id     # session_id
    cs_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
    body += struct.pack(">H", len(cs_bytes)) + cs_bytes
    body += bytes([len(compression_methods)]) + bytes(compression_methods)
    if extensions is not None:
        ext_bytes = bytearray()
        for etype, ebody in extensions:
            ext_bytes += struct.pack(">HH", etype, len(ebody)) + ebody
        body += struct.pack(">H", len(ext_bytes)) + ext_bytes

    # handshake header: HandshakeType(1) + uint24 length
    out = bytearray()
    out += bytes([1])
    out += struct.pack(">I", len(body))[1:]   # uint24
    out += body
    return bytes(out)


def ext_sni(host: bytes) -> bytes:
    """server_name extension body — host_name list with one entry."""
    name_entry = bytes([0x00]) + struct.pack(">H", len(host)) + host
    return struct.pack(">H", len(name_entry)) + name_entry


def ext_alpn(protos: list[bytes]) -> bytes:
    """ALPN extension body — list of protocol_name."""
    proto_list = b"".join(bytes([len(p)]) + p for p in protos)
    return struct.pack(">H", len(proto_list)) + proto_list


def ext_supported_versions_ch(versions: list[int]) -> bytes:
    """supported_versions (ClientHello) — u8 list length + u16 versions."""
    v = b"".join(struct.pack(">H", x) for x in versions)
    return bytes([len(v)]) + v


def ext_sig_algs(algs: list[int]) -> bytes:
    """signature_algorithms — u16 list length + u16 scheme IDs."""
    body = b"".join(struct.pack(">H", a) for a in algs)
    return struct.pack(">H", len(body)) + body


def ext_supported_groups(groups: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", g) for g in groups)
    return struct.pack(">H", len(body)) + body


def write(name: str, payload: bytes) -> None:
    p = HERE / name
    p.write_bytes(payload)
    print(f"wrote {p.name}  ({len(payload)} bytes)")


def main() -> None:
    # 1. Minimal TLS 1.0 ClientHello with no extensions (= ancient client).
    write("01-tls10-no-ext.bin", build_client_hello(
        legacy_version=0x0301,
        ciphers=[0x0005],                  # TLS_RSA_WITH_RC4_128_SHA
        compression_methods=[0x00],
        extensions=None,
    ))

    # 2. TLS 1.2 ClientHello with SNI + ALPN h2.
    write("02-tls12-sni-alpn.bin", build_client_hello(
        legacy_version=0x0303,
        ciphers=[0xc02f, 0xc030, 0x009c, 0x009d],
        compression_methods=[0x00],
        extensions=[
            (0x0000, ext_sni(b"example.com")),
            (0x0010, ext_alpn([b"h2", b"http/1.1"])),
            (0x000d, ext_sig_algs([0x0403, 0x0804, 0x0805])),
        ],
    ))

    # 3. TLS 1.3 ClientHello with supported_versions, GREASE in ciphers
    #    and extensions to exercise the GREASE filter branch.
    write("03-tls13-grease.bin", build_client_hello(
        legacy_version=0x0303,
        ciphers=[0x0a0a, 0x1301, 0x1302, 0x1303],  # GREASE + TLS_AES_128/256
        compression_methods=[0x00],
        extensions=[
            (0x0a0a, b""),                    # GREASE ext, empty body
            (0x0000, ext_sni(b"unmask.sh")),
            (0x0010, ext_alpn([b"h2"])),
            (0x002b, ext_supported_versions_ch([0x0a0a, 0x0304, 0x0303])),
            (0x000d, ext_sig_algs([0x0a0a, 0x0403, 0x0804])),
            (0x000a, ext_supported_groups([0x001d, 0x0017])),
        ],
    ))

    # 4. ClientHello with maximum cipher count near the parser cap to
    #    exercise the truncate-past-256 branch.  Use sequential IDs that
    #    are not GREASE.
    many_ciphers = [0x1300 | (i & 0xff) for i in range(300)]
    write("04-cipher-overflow.bin", build_client_hello(
        legacy_version=0x0303,
        ciphers=many_ciphers,
        compression_methods=[0x00],
        extensions=[
            (0x0000, ext_sni(b"a")),
        ],
    ))

    # 5. ClientHello with an empty extensions block (= len 0, well-formed).
    write("05-empty-ext-block.bin", build_client_hello(
        legacy_version=0x0303,
        ciphers=[0x1301],
        compression_methods=[0x00],
        extensions=[],
    ))

    # 6. ClientHello with non-empty session_id (= TLS 1.3 middlebox compat
    #    mode).  32 bytes of session_id.
    write("06-tls13-mbox-compat.bin", build_client_hello(
        legacy_version=0x0303,
        ciphers=[0x1301, 0x1302],
        compression_methods=[0x00],
        extensions=[
            (0x002b, ext_supported_versions_ch([0x0304])),
            (0x000d, ext_sig_algs([0x0804])),
            (0x0000, ext_sni(b"x.test")),
        ],
        session_id=bytes(range(32)),
    ))

    # 7. ClientHello with one extension body that is the maximum size we
    #    can put inside u16 length without overflow (= 65530 bytes).  This
    #    exercises the per-extension length validation.
    big_ext_body = b"\x00" * 65530
    write("07-large-ext-body.bin", build_client_hello(
        legacy_version=0x0303,
        ciphers=[0x1301],
        compression_methods=[0x00],
        extensions=[
            (0x1234, big_ext_body),
        ],
    ))

    # 8. ClientHello with ALPN proto length set to 1 byte ("X").  Trips
    #    the alpn_first == alpn_last branch.
    write("08-alpn-single-char.bin", build_client_hello(
        legacy_version=0x0303,
        ciphers=[0x1301],
        compression_methods=[0x00],
        extensions=[
            (0x0010, ext_alpn([b"X"])),
        ],
    ))

    # 9. Borderline-malformed input that still parses up to the cipher
    #    section, then dies at compression_methods.  Useful as a mutation
    #    starting point for libFuzzer.
    body = bytearray()
    body += struct.pack(">H", 0x0303)
    body += bytes([0xCC] * 32)
    body += bytes([0])                       # session_id = 0
    body += struct.pack(">H", 2) + b"\x13\x01"   # ciphers
    # truncate before compression methods
    raw = bytes([1]) + struct.pack(">I", len(body))[1:] + body
    write("09-truncated-after-ciphers.bin", raw)

    # 10. Pure noise seed (1 byte of HandshakeType=1, otherwise random-looking
    #     constant).  libFuzzer mutates from short seeds aggressively.
    write("10-tiny.bin", b"\x01")


if __name__ == "__main__":
    main()
