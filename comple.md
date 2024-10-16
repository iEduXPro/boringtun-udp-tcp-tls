##~/Library/Android/sdk/ndk/25.2.9519653/


# Android SDK 路径
export ANDROID_SDK_ROOT=$HOME/Library/Android/sdk
export PATH=$PATH:$ANDROID_SDK_ROOT/tools
export PATH=$PATH:$ANDROID_SDK_ROOT/platform-tools
# NDK 路径
export ANDROID_NDK_HOME=$ANDROID_SDK_ROOT/ndk/25.2.9519653
export PATH=$PATH:$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/
export target=aarch64-linux-android
export api=30
export android_tools="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin"
export CC_aarch64_linux_android="${target}${api}-clang"


export HOST_OS=`uname -s | tr "[:upper:]" "[:lower:]"`
export HOST_ARCH=`uname -m | tr "[:upper:]" "[:lower:]"`
export NDK_HOME="/Users/haogle/Library/Android/sdk/ndk/25.2.9519653"
export TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64"
export AR="llvm-ar"
export PATH="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin/":$PATH
export target=aarch64-linux-android
export api=30
export android_tools="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH/bin"
export CC_aarch64_linux_android="$android_tools/${target}${api}-clang"
export AR_aarch64_linux_android="$android_tools/$AR"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$android_tools/$AR"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$android_tools/${target}${api}-clang"

调试时运行
- cargo run --bin boringtun-cli -- --disable-drop-privileges -f utun

如何配置
- on macos for client
  - RUST_LOG=debug target/release/udp2tcp --udp-listen 0.0.0.0:8765 --tcp-forward 192.168.22.33:7791
  - sudo wg set utun6 private-key ./private.key peer L61VUVOoz9agLjwwt5Sx8QeeXh8dQoNzcUv3QJqt0AU= preshared-key ./preshared.key endpoint 127.0.0.1:8765 10.22.0.0/16,192.168.0.0/16 persistent-keepalive 25
  - sudo ifconfig utun6 inet 10.22.0.2/24 10.22.0.2 alias && sudo ifconfig utun6 up && sudo route -q -n add -inet 0.0.0.0/1 -interface utun6
