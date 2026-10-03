#!/bin/bash
# Usage: ./obj_build.sh <tag> <target1.o> [target2.o ...]

set -e

# Terminal colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$#" -lt 1 ]; then
    echo -e "${RED}Error: Tag required.${NC}"
    echo "Usage: $0 <tag> [target1.o target2.o ...]"
    exit 1
fi

TAG="$1"
shift

PROJECT_DIR="$PWD"
LOG_DIR="${HOME}/obj_build_logs"
mkdir -p "$LOG_DIR"
LOG="${LOG_DIR}/obj_${TAG}_$(date +%Y%m%d_%H%M%S).log"

# Toolchain setup
export ARCH=arm64
export CROSS_COMPILE="${PROJECT_DIR}/toolchain/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin/aarch64-linux-android-"
export CLANG_TOOL_PATH="${PROJECT_DIR}/toolchain/clang/host/linux-x86/clang-r383902/bin/"
export PATH="${CLANG_TOOL_PATH}:${PATH//"${CLANG_TOOL_PATH}:"}"
export BSP_BUILD_FAMILY=qogirl6
export BSP_BUILD_ANDROID_OS=y

# Run build
set +e
make -k -C "$PROJECT_DIR" O="${PROJECT_DIR}/out" BSP_BUILD_DT_OVERLAY=y CC=clang LD=ld.lld ARCH=arm64 CLANG_TRIPLE=aarch64-linux-gnu- KCFLAGS=-ferror-limit=0 "$@" > "$LOG" 2>&1
MAKE_STATUS=$?

echo "----------------------------------------"
echo "Log file : $LOG"

ERR_COUNT=$(grep -iE 'error:|no rule to make|\*\*\*' "$LOG" | wc -l || true)
echo "Errors   : $ERR_COUNT"

if [ "$MAKE_STATUS" -eq 0 ] && [ "$ERR_COUNT" -eq 0 ]; then
    echo -e "\n${GREEN}[OK] Build successful.${NC}"
else
    echo -e "\n${RED}[FAIL] Build errors:${NC}"
    grep -iE 'error:|no rule to make|\*\*\*' "$LOG" | sed "s#${PROJECT_DIR}/##; s#^\.\./##" | sort -u
    exit 1
fi
