#!/usr/bin/env python3
"""Prepare the exact tested IBM GB7H 800 GB package. No device access."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

SOURCE_SHA256 = '4c4bb135318360daf3c16f28bd7f3a2acaf1356f17deea4d5731190ede03eb59'
PREPARED_SHA256 = 'c50ee13f372d4ad93c09df96cda59a39b1a98a86f605635aacfda1dba3efb909'
SALT = b'These go to eleven.'
UNFORMATTED = b'\xff' * 15 + b'\x03' + b'\xff' * 8


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def seal(header, body):
    header = bytearray(header)
    require(len(header) == 256, 'DOB header must be 256 bytes')
    struct.pack_into('<I', header, 8, 256 + len(body))
    struct.pack_into('<II', header, 16, len(body), len(body))
    header[0xc0:0xd0] = hashlib.md5(body).digest()
    header[0xe0:0xf0] = hashlib.md5(SALT + header[:224]).digest()
    return bytes(header) + body


def unlock(level):
    require(level in (2, 255, 256), 'Use 2, 255, or 256; zero cycles levels')
    header = bytearray(256)
    header[:8] = b'DOB UNLK'
    struct.pack_into('<I', header, 12, 256)
    struct.pack_into('<I', header, 24, 0x22)
    struct.pack_into('<I', header, 0x50, level)
    return seal(header, bytes(256))


def build(source):
    require(sha(source) == SOURCE_SHA256, 'Wrong source: only the documented gb7h_all.dob is accepted')
    require(source[:8] == b'DOB CFRM', 'Not the expected CFRM container')
    # Offsets are pinned to the exact source hash, not inferred for other images.
    components = [('CPU0', 0x4a80, 0x2dae0), ('CUST', 0x32560, 0x2940),
                  ('CPU1', 0x93920, 0x2f7a0)]
    selected = []
    manifest = []
    for tag, offset, length in components:
        part = source[offset:offset + length]
        require(part[:8] == b'DOB ' + tag.encode(), 'Component tag mismatch')
        require(struct.unpack_from('<I', part, 8)[0] == length, 'Component length mismatch')
        if tag == 'CPU1':
            require(part[0x45] == 8, 'Not the 800 GB CPU1 selector')
        selected.append(part)
        manifest.append(dict(tag=tag, offset=offset, length=length, sha256=sha(part)))
    candidate = seal(source[:256], b''.join(selected))
    require(sha(candidate) == PREPARED_SHA256, 'Prepared image differs from tested package')
    return candidate, manifest


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=Path, help='Your locally obtained gb7h_all.dob')
    ap.add_argument('--out', type=Path, required=True, help='New private output directory')
    args = ap.parse_args()
    candidate, components = build(args.source.read_bytes())
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = {'gb7h-800-only-no-boot.dob': candidate,
             'native-unformatted-file0a.bin': UNFORMATTED}
    for name, data in files.items():
        (args.out / name).write_bytes(data)
    manifest = dict(source_sha256=SOURCE_SHA256, components=components,
                    files={name: dict(bytes=len(data), sha256=sha(data)) for name, data in files.items()})
    (args.out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Prepared CPU0 + CUST + 800 GB CPU1; BOOT excluded.')
    print('SHA256:', sha(candidate))


if __name__ == '__main__':
    main()
