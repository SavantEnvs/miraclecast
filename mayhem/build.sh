#!/usr/bin/env bash
# mayhem/build.sh — build miraclecast's fuzz harnesses (sanitized) and its own
# `check` test suite (normal flags). Runs as `mayhem` in /mayhem; offline-safe
# (only apt-installed deps), idempotent. All build dirs live under build/,
# which upstream's .gitignore already ignores.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS
cd "$SRC"

meson_setup() {  # <dir> <c_args> <extra opts...>
  local dir="$1" cargs="$2"; shift 2
  if [ -f "$dir/build.ninja" ]; then
    meson setup --reconfigure "$dir" -Dc_args="$cargs" -Dc_link_args="$cargs" "$@"
  else
    meson setup "$dir" --buildtype=plain -Dc_args="$cargs" -Dc_link_args="$cargs" "$@"
  fi
}

# 1) Upstream's meson build of the shared library, sanitized + DWARF 3.
# -fsanitize=fuzzer-no-link: SanCov edges in the library itself, so libFuzzer and
# Mayhem see coverage of the parser, not only of the harness.
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
meson_setup build/fuzz "$FUZZ_CFLAGS" -Dbuild-tests=false
ninja -C build/fuzz -j"$MAYHEM_JOBS" src/shared/libmiracle-shared.a
LIB=build/fuzz/src/shared/libmiracle-shared.a

# 2) Harnesses: libFuzzer binary + standalone reproducer each.
mkdir -p build/obj
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o build/obj/lsan_off.o
COMMON="-D_GNU_SOURCE -std=gnu11 -O1 -Ibuild/fuzz -include build/fuzz/config.h -Isrc/shared -Isrc -Imayhem/harnesses"
GLIB_CFLAGS="$(pkg-config --cflags glib-2.0)"; GLIB_LIBS="$(pkg-config --libs glib-2.0)"
SD_LIBS="$(pkg-config --libs libsystemd)"

link_both() {  # <name> <sources/flags...>
  local name="$1"; shift
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$@" build/obj/lsan_off.o -o "/mayhem/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" "$@" build/obj/lsan_off.o -o "/mayhem/$name-standalone"
}

link_both fuzz_rtsp_stream $COMMON mayhem/harnesses/fuzz_rtsp_stream.c "$LIB" $SD_LIBS
link_both fuzz_rtsp_raw    $COMMON mayhem/harnesses/fuzz_rtsp_raw.c    "$LIB" $SD_LIBS
link_both fuzz_wpas        $COMMON mayhem/harnesses/fuzz_wpas.c        "$LIB" $SD_LIBS
# miracle-uibcctl.c carries main() next to its parsers: rename it in that TU only.
$CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS $COMMON -Isrc/uibc -Dmain=uibc_main -c src/uibc/miracle-uibcctl.c \
  -o build/obj/miracle-uibcctl.o
link_both fuzz_uibc        $COMMON -Isrc/uibc mayhem/harnesses/fuzz_uibc.c \
  build/obj/miracle-uibcctl.o "$LIB" $SD_LIBS -lm
link_both fuzz_dhcp_server $COMMON -Isrc/dhcp $GLIB_CFLAGS mayhem/harnesses/fuzz_dhcp_server.c \
  src/dhcp/server.c src/dhcp/common.c $GLIB_LIBS
link_both fuzz_dhcp_client $COMMON -Isrc/dhcp $GLIB_CFLAGS mayhem/harnesses/fuzz_dhcp_client.c \
  src/dhcp/client.c src/dhcp/common.c src/dhcp/ipv4ll.c $GLIB_LIBS
link_both fuzz_dhcpv6_client $COMMON -Isrc/dhcp $GLIB_CFLAGS mayhem/harnesses/fuzz_dhcpv6_client.c \
  src/dhcp/client.c src/dhcp/common.c src/dhcp/ipv4ll.c $GLIB_LIBS

# wifid's supplicant event handlers: the harness #includes wifid-supplicant.c
# (its connect path is static) and links the link/peer objects next to it.
link_both fuzz_wifid_supplicant $COMMON -Isrc/wifi $GLIB_CFLAGS mayhem/harnesses/fuzz_wifid_supplicant.c \
  src/wifi/wifid-link.c src/wifi/wifid-peer.c "$LIB" $SD_LIBS $GLIB_LIBS

link_both fuzz_ctl_sink    $COMMON -Isrc/ctl $GLIB_CFLAGS mayhem/harnesses/fuzz_ctl_sink.c \
  src/ctl/ctl-sink.c src/ctl/wfd.c "$LIB" $SD_LIBS $GLIB_LIBS

# 3) Upstream test suite (check: test_rtsp, test_wpas) with NORMAL flags.
meson_setup build/tests "$COVERAGE_FLAGS" -Dbuild-tests=true
ninja -C build/tests -j"$MAYHEM_JOBS" test/test_rtsp test/test_wpas
