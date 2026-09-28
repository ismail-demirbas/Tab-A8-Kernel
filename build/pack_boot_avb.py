#!/usr/bin/env python3

import struct
import sys
from pathlib import Path

PARTITION_SIZE = 64 * 1024 * 1024
FOOTER_SIZE = 64
VBMETA_ALIGNMENT = 4096
SEANDROID_MAGIC = b"SEANDROIDENFORCE"


def align_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def error(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


if len(sys.argv) != 4:
    print(
        f"Usage: {sys.argv[0]} <payload> <avb_dir> <output>",
        file=sys.stderr,
    )
    sys.exit(2)


payload_path = Path(sys.argv[1])
avb_dir = Path(sys.argv[2])
output_path = Path(sys.argv[3])

vbmeta_path = avb_dir / "vbmeta.bin"
footer_path = avb_dir / "footer.bin"

if not payload_path.is_file():
    error(f"Payload not found: {payload_path}")

if not vbmeta_path.is_file():
    error(f"VBMeta not found: {vbmeta_path}")

if not footer_path.is_file():
    error(f"Footer not found: {footer_path}")


payload = payload_path.read_bytes()
vbmeta = vbmeta_path.read_bytes()
footer = bytearray(footer_path.read_bytes())


# Validate AVB template

if len(footer) != FOOTER_SIZE:
    error(f"Footer size is {len(footer)}, expected {FOOTER_SIZE}")

if footer[0:4] != b"AVBf":
    error("Invalid AVB footer magic")

if vbmeta[0:4] != b"AVB0":
    error("Invalid VBMeta magic")


template_vbmeta_size = struct.unpack(">Q", footer[28:36])[0]

if template_vbmeta_size != len(vbmeta):
    error(
        f"Footer says VBMeta size is {template_vbmeta_size}, "
        f"but vbmeta.bin is {len(vbmeta)} bytes"
    )


# Samsung boot image contains this 16-byte marker
# between the AOSP boot image payload and AVB data.

aosp_image_size = len(payload) + len(SEANDROID_MAGIC)

vbmeta_offset = align_up(
    aosp_image_size,
    VBMETA_ALIGNMENT,
)

end_without_footer = vbmeta_offset + len(vbmeta)

if end_without_footer > PARTITION_SIZE - FOOTER_SIZE:
    error(
        f"Boot image is too large:\n"
        f"  payload       = {len(payload)}\n"
        f"  aosp size     = {aosp_image_size}\n"
        f"  vbmeta offset = {vbmeta_offset}\n"
        f"  vbmeta size   = {len(vbmeta)}\n"
        f"  partition     = {PARTITION_SIZE}"
    )


# MagiskBoot changes only these two AVB footer fields
# in the behavior we verified from the working image.

struct.pack_into(
    ">Q",
    footer,
    12,
    aosp_image_size,
)

struct.pack_into(
    ">Q",
    footer,
    20,
    vbmeta_offset,
)


# Build final 64 MiB image.

with output_path.open("wb") as image:
    image.write(payload)

    # Samsung SEANDROID marker
    image.write(SEANDROID_MAGIC)

    # Align VBMeta to 4096 bytes
    image.write(
        b"\x00" * (vbmeta_offset - aosp_image_size)
    )

    # Preserve the device-specific VBMeta exactly.
    image.write(vbmeta)

    # Fill remaining partition space before the footer.
    image.write(
        b"\x00" * (
            PARTITION_SIZE
            - FOOTER_SIZE
            - image.tell()
        )
    )

    # AVB footer must be the final 64 bytes.
    image.write(footer)


final_size = output_path.stat().st_size

if final_size != PARTITION_SIZE:
    error(
        f"Final image size is {final_size}, "
        f"expected {PARTITION_SIZE}"
    )


print(f"Payload size : {len(payload)}")
print(f"AOSP size    : {aosp_image_size}")
print(f"VBMeta offset: {vbmeta_offset}")
print(f"VBMeta size  : {len(vbmeta)}")
print(f"Output size  : {final_size}")
print(f"Output       : {output_path}")
