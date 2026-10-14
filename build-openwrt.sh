#!/bin/sh
# 为 OpenWrt 路由器交叉编译 domain-socks（纯 Go、CGO_ENABLED=0 静态链接，
# 不依赖设备上的 libc，scp 即可运行）。
#
# 不带参数运行默认构建 Newifi3（联想 Newifi 3 / MT7621AT，
# OpenWrt ramips/mt7621 子目标 mipsel_1004kc）：
#
#   ./build-openwrt.sh
#
# 也可显式指定任意 GOOS/GOARCH（含斜杠的 target 形式）：
#
#   ./build-openwrt.sh linux/mipsle              # 同默认（MT7621 系列路由）
#   ./build-openwrt.sh linux/arm64               # Filogic 820/830 等新平台
#   ./build-openwrt.sh linux/arm linux/amd64     # 一次多目标
#
# 环境变量覆盖：GOMIPS（默认 softfloat）、GOARM（默认 7）。
set -eu

if [ "$#" -eq 0 ]; then
    # Newifi3 / MT7621：OpenWrt mipsel_1004kc 工具链是 soft-float ABI
    set -- linux/mipsle
fi

gomips="${GOMIPS:-softfloat}"
goarm="${GOARM:-7}"

for target in "$@"; do
    case "$target" in
    */*) ;;
    *) echo "target must be GOOS/GOARCH (e.g. linux/mipsle), got: $target" >&2; exit 2 ;;
    esac
    goos="${target%%/*}"
    goarch="${target##*/}"

    # mips/mipsle：OpenWrt 全线 soft-float。显式固定，防止环境里遗留的
    # GOMIPS=hardfloat 产出含 FP 指令的二进制，在 soft-float 内核上直接
    # SIGILL（表现为"装了跑不起来"）。
    case "$goarch" in
    mips|mipsle) export GOMIPS="$gomips" ;;
    esac
    # 32 位 ARM 路由（mvebe/armvirt 等）基本为 ARMv7；v5 二进制虽兼容性
    # 更好，但主流 OpenWrt arm 目标已是 v7，按 v7 构建。
    case "$goarch" in
    arm) export GOARM="$goarm" ;;
    esac

    suffix=""
    case "$goarch" in
    mips|mipsle) suffix="-softfloat" ;;
    esac
    out="domain-socks-${goos}-${goarch}${suffix}"

    echo "building ${goos}/${goarch} (GOMIPS=${GOMIPS:-} GOARM=${GOARM:-}) -> ${out}"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -trimpath -ldflags '-s -w' -o "$out" .

    ls -l "$out"
    # 架构 sanity check（CI 与手动构建都能立刻看出是不是目标平台）
    if command -v file >/dev/null 2>&1; then
        file "$out"
    fi
done
