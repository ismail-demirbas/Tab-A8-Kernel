#!/bin/bash

# Terminal colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

export CROSS_COMPILE=$(pwd)/toolchain/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin/aarch64-linux-android-
export ARCH=arm64
export CLANG_TOOL_PATH=$(pwd)/toolchain/clang/host/linux-x86/clang-r383902/bin/
export PATH=${CLANG_TOOL_PATH}:${PATH//"${CLANG_TOOL_PATH}:"}

export BSP_BUILD_FAMILY=qogirl6
export DTC_OVERLAY_TEST_EXT=$(pwd)/tools/mkdtimg/ufdt_apply_overlay
export DTC_OVERLAY_VTS_EXT=$(pwd)/tools/mkdtimg/ufdt_verify_overlay_host
export BSP_BUILD_ANDROID_OS=y

make -C $(pwd) O=$(pwd)/out BSP_BUILD_DT_OVERLAY=y CC=clang LD=ld.lld ARCH=arm64 CLANG_TRIPLE=aarch64-linux-gnu- gta8xx_eur_open_defconfig

make -C $(pwd) O=$(pwd)/out BSP_BUILD_DT_OVERLAY=y CC=clang LD=ld.lld ARCH=arm64 CLANG_TRIPLE=aarch64-linux-gnu- KBUILD_SYMTYPES=1 -j12

if [ $? -ne 0 ]; then
    echo "-----------------------------------------------"
    echo -e "${RED}Kernel build failed!${NC}"
    echo "-----------------------------------------------"
    exit 1
fi

cp out/arch/arm64/boot/Image $(pwd)/arch/arm64/boot/Image

MKBOOTIMG="$(pwd)/mkbootimg/mkbootimg.py"
OUT_KERNEL="$(pwd)/out/arch/arm64/boot/Image"
DTB_RAMDISK_DIR="$(pwd)/build"
AVB_PACKER="$(pwd)/build/pack_boot_avb.py"
MAGISKBOOT="$(pwd)/build/magiskboot"

CMDLINE="console=ttyS1,115200n8"
BASE="0x00000000"
KOFFSET="0x00008000"
ROFFSET="0x01000000"
SECOFFSET="0x00000000"
DTBOFFSET="0x01f00000"
TAGSOFFSET="0x00000100"
PAGESZ="2048"

build_boot() {
    local NAME=$1
    local BOARD=$2
    local DEVDIR=$3

    local PAYLOAD="$(pwd)/out/${NAME}_payload.img"
    local OUTPUT="$(pwd)/out/${NAME}_boot.img"
    local AVB_DIR="$DEVDIR"
    local RAMDISK_GZ="$(pwd)/out/${NAME}_ramdisk.gz"

    echo "-----------------------------------------------"
    echo "Building boot.img for $NAME..."
    echo "-----------------------------------------------"

    "$MAGISKBOOT" compress=gzip \
        "$DEVDIR/ramdisk.cpio" \
        "$RAMDISK_GZ"

    if [ $? -ne 0 ]; then
        echo -e "${RED}Ramdisk compression failed for $NAME!${NC}"
        return 1
    fi

    $MKBOOTIMG \
        --header_version 2 \
        --kernel "$OUT_KERNEL" \
        --ramdisk "$RAMDISK_GZ" \
        --dtb "$DEVDIR/dtb" \
        --cmdline "$CMDLINE" \
        --base "$BASE" \
        --kernel_offset "$KOFFSET" \
        --ramdisk_offset "$ROFFSET" \
        --second_offset "$SECOFFSET" \
        --dtb_offset "$DTBOFFSET" \
        --tags_offset "$TAGSOFFSET" \
        --board "$BOARD" \
        --pagesize "$PAGESZ" \
        --os_version 11.0.0 \
        --os_patch_level 2025-08 \
        --output "$PAYLOAD"

    if [ $? -ne 0 ]; then
        echo -e "${RED}mkbootimg failed for $NAME!${NC}"
        rm -f "$RAMDISK_GZ" "$PAYLOAD"
        return 1
    fi

    "$AVB_PACKER" \
        "$PAYLOAD" \
        "$AVB_DIR" \
        "$OUTPUT"

    if [ $? -ne 0 ]; then
        echo -e "${RED}AVB packaging failed for $NAME!${NC}"
        rm -f "$RAMDISK_GZ" "$PAYLOAD"
        return 1
    fi

    rm -f "$PAYLOAD" "$RAMDISK_GZ"

    echo "Created: $OUTPUT"
}

build_boot "X200" "SRPUI28B006" "$DTB_RAMDISK_DIR/sm-x200" || exit 1
build_boot "X205" "SRPUI28A006" "$DTB_RAMDISK_DIR/sm-x205" || exit 1
build_boot "X207" "SRPUJ01A006" "$DTB_RAMDISK_DIR/sm-x207" || exit 1

echo "-----------------------------------------------"
echo -e "${GREEN}[OK] Build finished successfully!${NC}"
echo "-----------------------------------------------"
