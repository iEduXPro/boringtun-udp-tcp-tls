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
  - sudo wg set utun6 private-key ./private.key peer L61VUVOoz9agLjwwt5Sx8QeeXh8dQoNzcUv3QJqt0AU= preshared-key ./preshared.key endpoint 127.0.0.1:8765 allowed-ips 0.0.0.0/0 persistent-keepalive 25
  - sudo ifconfig utun6 inet 10.22.0.2/24 10.22.0.2 alias && sudo ifconfig utun6 up && sudo route -q -n add -inet 0.0.0.0/1 -interface utun6

udp No.1 packet
[1, 0, 0, 0, 245, 221, 96, 129, 179, 219, 215, 148, 121, 130, 134, 4, 70, 212, 179, 149, 31, 59, 253, 94, 123, 20, 24, 178, 158, 13, 9, 188, 68, 172, 236, 72, 232, 58, 82, 57, 199, 64, 13, 105, 93, 163, 145, 66, 41, 249, 204, 47, 173, 172, 252, 83, 129, 119, 108, 181, 11, 121, 81, 45, 80, 191, 252, 131, 3, 21, 230, 93, 195, 225, 247, 122, 12, 188, 141, 162, 35, 114, 228, 117, 141, 252, 133, 22, 130, 43, 106, 64, 146, 1, 170, 75, 39, 161, 242, 37, 163, 40, 219, 209, 15, 156, 218, 214, 255, 125, 151, 198, 120, 96, 60, 205, 186, 234, 86, 6, 116, 233, 63, 47, 44, 157, 221, 245, 9, 238, 19, 79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

[0, 92, 2, 0, 0, 0, 247, 227, 174, 130, 245, 221, 96, 129, 40, 191, 182, 248, 31, 97, 190, 69, 101, 119, 185, 240, 84, 249, 46, 243, 57, 210, 167, 92, 162, 97, 220, 212, 19, 254, 149, 172, 25, 251, 57, 11, 98, 113, 171, 244, 77, 161, 122, 204, 159, 85, 209, 153, 90, 137, 217, 153, 208, 187, 60, 191, 191, 253, 125, 143, 23, 237, 236, 167, 3, 207, 113, 179, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]


// udp over tcp
[0, 92, 2, 0, 0, 0, 88, 150, 133, 201, 1, 96, 97, 93, 140, 242, 221, 17, 204, 24, 240, 135, 100, 32, 142, 76, 69, 149, 224, 119, 142, 151, 56, 134, 112, 222, 131, 208, 169, 154, 152, 112, 219, 212, 111, 11, 20, 63, 144, 67, 140, 198, 197, 78, 198, 146, 41, 237, 66, 118, 204, 149, 74, 225, 119, 38, 5, 132, 132, 135, 218, 227, 10, 3, 64, 114, 197, 205, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

// new code
[0, 92, 2, 0, 0, 0, 78, 204, 3, 141, 25, 221, 96, 129, 27, 196, 168, 210, 29, 16, 183, 165, 145, 194, 193, 122, 81, 45, 234, 170, 98, 229, 149, 99, 14, 121, 116, 26, 86, 211, 140, 13, 172, 242, 164, 74, 96, 73, 95, 159, 18, 17, 69, 130, 201, 90, 4, 253, 100, 9, 254, 39, 28, 40, 194, 7, 19, 103, 22, 137, 159, 32, 115, 85, 11, 102, 113, 121, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

// from:SockAddr { ss_len: 0, ss_family: 0, len: 0 }