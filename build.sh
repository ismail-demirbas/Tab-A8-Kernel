#!/bin/bash

# Terminal colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
fail() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

center_text() {
    local text="$1" color="${2:-$NC}" width
    width=$(tput cols 2>/dev/null) || width=80
    [[ "$width" =~ ^[0-9]+$ ]] || width=80
    local padding=$(((width - ${#text}) / 2))
    (( padding < 0 )) && padding=0
    printf "%*s%b%s%b\n" "$padding" "" "$color" "$text" "$NC"
}

# Default: KSU + SUSFS enabled
KSU_OPTION=y

usage() {
    echo "Usage: ./build.sh [OPTIONS]"
    echo
    echo "Options:"
    echo "  -ksu y       Enable KSU + SUSFS"
    echo "  -ksu n       Disable KSU + SUSFS"
    echo "  -h, --help   Show this help message"
    echo
    echo "Default: KSU + SUSFS enabled"
    echo
    echo "Examples:"
    echo "  ./build.sh"
    echo "  ./build.sh -ksu y"
    echo "  ./build.sh -ksu n"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -ksu|--ksu)
            if [[ $# -lt 2 ]]; then
                echo -e "${RED}Error: Missing value for $1. Use y or n.${NC}"
                echo
                usage
                exit 1
            fi

            case "${2,,}" in
                y) KSU_OPTION=y ;;
                n) KSU_OPTION=n ;;
                *)
                    echo -e "${RED}Error: Invalid KSU option: $2${NC}"
                    echo "Valid values: y or n"
                    echo
                    usage
                    exit 1
                    ;;
            esac

            shift 2
            ;;

        -h|--help)
            usage
            exit 0
            ;;

        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            echo
            usage
            exit 1
            ;;
    esac
done

export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=arm64
export CLANG_DIR=$(pwd)/toolchain/neutron-clang
export CLANG_TOOL_PATH=$CLANG_DIR/bin/
export PATH=${CLANG_TOOL_PATH}:${PATH//"${CLANG_TOOL_PATH}:"}

export GCC_DIR=$(pwd)/toolchain/gcc-aarch64
export PATH=${GCC_DIR}/bin:${PATH}

if ! command -v aarch64-linux-gnu-elfedit >/dev/null; then
    echo "-----------------------------------------------"
    echo "aarch64-linux-gnu- binutils not found! Downloading..."
    echo "-----------------------------------------------"

    if ! command -v git >/dev/null; then
        echo -e "${RED}Missing tool: git${NC}"
        echo "  Debian/Ubuntu : sudo apt install git"
        echo "  Arch          : sudo pacman -S git"
        echo "  Fedora        : sudo dnf install git"
        exit 1
    fi

    rm -rf "$GCC_DIR"
    git clone --depth=1 -b lineage-19.1 \
        https://github.com/LineageOS/android_prebuilts_gcc_linux-x86_aarch64_aarch64-linux-android-4.9 \
        "$GCC_DIR" \
        || { echo -e "${RED}Failed to download aarch64 GCC${NC}"; rm -rf "$GCC_DIR"; exit 1; }
    rm -rf "$GCC_DIR/.git"

    command -v aarch64-linux-gnu-elfedit >/dev/null \
        || { echo -e "${RED}aarch64-linux-gnu-elfedit still not found${NC}"; rm -rf "$GCC_DIR"; exit 1; }
fi

if [ ! -x "$CLANG_DIR/bin/clang" ]; then
    echo "-----------------------------------------------"
    echo "Toolchain not found! Downloading Neutron-Clang..."
    echo "-----------------------------------------------"

    for dep in curl wget strings zstd tar sha256sum file; do
        if ! command -v $dep >/dev/null; then
            echo -e "${RED}Missing tool: $dep${NC}"
            echo "  Debian/Ubuntu : sudo apt install curl wget binutils zstd tar coreutils file"
            echo "  Arch          : sudo pacman -S curl wget binutils zstd tar coreutils file"
            echo "  Fedora        : sudo dnf install curl wget binutils zstd tar coreutils file"
            exit 1
        fi
    done

    mkdir -p "$CLANG_DIR"
    pushd "$CLANG_DIR" > /dev/null || exit 1

    curl -fsSL https://raw.githubusercontent.com/Neutron-Toolchains/antman/main/antman -o antman \
        || { echo -e "${RED}Failed to download antman${NC}"; popd > /dev/null; rm -rf "$CLANG_DIR"; exit 1; }

    bash antman -S 2>&1 | tee antman.log
    if [ "${PIPESTATUS[0]}" -ne 0 ]; then
        echo -e "${RED}antman sync failed${NC}"
        popd > /dev/null
        rm -rf "$CLANG_DIR"
        exit 1
    fi

    if grep -q "older than the minimum required" antman.log; then
        echo "Host glibc too old, patching toolchain..."
        bash antman --patch=glibc \
            || { echo -e "${RED}glibc patch failed${NC}"; popd > /dev/null; rm -rf "$CLANG_DIR"; exit 1; }
    fi
    rm -f antman.log

    popd > /dev/null
fi

export BSP_BUILD_FAMILY=sharkl5Pro
export DTC_OVERLAY_TEST_EXT=$(pwd)/tools/mkdtimg/ufdt_apply_overlay
export DTC_OVERLAY_VTS_EXT=$(pwd)/tools/mkdtimg/ufdt_verify_overlay_host
export BSP_BUILD_ANDROID_OS=y

CONFIG_TARGETS=(gta8xx_eur_open_defconfig)

if [[ "$KSU_OPTION" == "y" ]]; then
    CONFIG_TARGETS+=(ksu_susfs.config)
fi

echo "KSU + SUSFS: $KSU_OPTION"

make -C "$(pwd)" O="$(pwd)/out" BSP_BUILD_DT_OVERLAY=y LLVM=1 ARCH=arm64 CLANG_TRIPLE=aarch64-linux-gnu- "${CONFIG_TARGETS[@]}" || fail "Kernel configuration failed. Check the defconfig and configuration fragments."

if ! make -C "$(pwd)" O="$(pwd)/out" BSP_BUILD_DT_OVERLAY=y LLVM=1 ARCH=arm64 CLANG_TRIPLE=aarch64-linux-gnu- KBUILD_SYMTYPES=1 -j12; then
    echo "-----------------------------------------------"
    echo -e "${RED}Kernel build failed!${NC}"
    echo "-----------------------------------------------"
    fail "Kernel compilation failed. Check the compiler output above."
fi

cp out/arch/arm64/boot/Image $(pwd)/arch/arm64/boot/Image
cp out/arch/arm64/boot/Image AnyKernel3/kernel \
    || fail "Failed to copy the compiled kernel Image to AnyKernel3/"

# Package UMS512 DTB and DTBO images
DTS_DIR="$(pwd)/out/arch/arm64/boot/dts/sprd"
MKDTIMG="$(pwd)/tools/mkdtimg/mkdtimg"
ANYKERNEL_DIR="$(pwd)/AnyKernel3"

DTB_FILES=(
    "$DTS_DIR/ums512.dtb"
    "$DTS_DIR/ums512-1h10-overlay.dtbo"
    "$DTS_DIR/ums512-1h10_go-overlay.dtbo"
    "$DTS_DIR/ums512-25c10-overlay.dtbo"
    "$DTS_DIR/ums512-2h10-overlay.dtbo"
    "$DTS_DIR/ums512-wifionly-overlay.dtbo"
)

[[ -x "$MKDTIMG" ]] || fail "mkdtimg not found or not executable."

for dt_file in "${DTB_FILES[@]}"; do
    [[ -s "$dt_file" ]] || fail "Missing DTB/DTBO file: $dt_file"
done

DT_TMP="$(mktemp -d "${TMPDIR:-/tmp}/ums512-dt.XXXXXX")"     || fail "Failed to create temporary directory."

cleanup_dt_tmp() {
    rm -rf "$DT_TMP"
}
trap cleanup_dt_tmp EXIT

# Create the single-entry UMS512 DTB table
"$MKDTIMG" create "$DT_TMP/dtb"     --page_size=2048 --version=0     "$DTS_DIR/ums512.dtb" --id=0x00000000 --rev=0x00000000     || fail "Failed to create DTB image."

# Create the five-entry DTBO table in stock order
"$MKDTIMG" create "$DT_TMP/dtbo.img"     --page_size=2048 --version=0     "$DTS_DIR/ums512-1h10-overlay.dtbo" --id=0x1100 --rev=0     "$DTS_DIR/ums512-1h10_go-overlay.dtbo" --id=0x1900 --rev=0     "$DTS_DIR/ums512-25c10-overlay.dtbo" --id=0x1100 --rev=0     "$DTS_DIR/ums512-2h10-overlay.dtbo" --id=0x2100 --rev=0     "$DTS_DIR/ums512-wifionly-overlay.dtbo" --id=0x1100 --rev=0     || fail "Failed to create DTBO image."

# Validate generated device tree images
"$MKDTIMG" dump "$DT_TMP/dtb" > /dev/null     || fail "Generated DTB image is invalid."

"$MKDTIMG" dump "$DT_TMP/dtbo.img" > /dev/null     || fail "Generated DTBO image is invalid."

# Copy generated images into AnyKernel3
cp "$DT_TMP/dtb" "$ANYKERNEL_DIR/dtb"     || fail "Failed to copy DTB image."

cp "$DT_TMP/dtbo.img" "$ANYKERNEL_DIR/dtbo.img"     || fail "Failed to copy DTBO image."

echo "UMS512 DTB/DTBO packaging completed successfully."
ls -lh "$ANYKERNEL_DIR/dtb" "$ANYKERNEL_DIR/dtbo.img"

cd AnyKernel3 || fail "Failed to enter AnyKernel3 directory."

if [[ "$KSU_OPTION" == "y" ]]; then
    KSU_SUFFIX="-KSU"
else
    KSU_SUFFIX=""
fi

command -v zip >/dev/null 2>&1 \
    || fail "Missing tool: zip. Please install the zip package."

ZIP_NAME="TabA8-Kernel-Extended${KSU_SUFFIX}-$(date +%Y%m%d).zip"

zip -r9 "../out/$ZIP_NAME" * -x .git README.md '*placeholder' \
    || fail "Failed to create kernel ZIP package."

cd .. || fail "Failed to return to the kernel source directory."

center_text "----------------------------------------------------------------------------"
center_text "[OK] Build finished successfully!" "$GREEN"
center_text "Kernel package: $ZIP_NAME"
center_text "----------------------------------------------------------------------------"
