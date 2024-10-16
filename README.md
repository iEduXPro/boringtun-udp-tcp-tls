## To hake boringTun.

- [X] TCP support for WireGuard
- [ ] TLS support for WireGuard

## Usage
To use tcp support for WireGuard. client side run boringTun and server side run boringTun or native WireGuard.

- client side  
 $>cargo run --bin boringtun-cli -- --disable-drop-privileges -f utun```

- server side  
 $> RUST_LOG=debug RUST_LOG=trace tcp2udp --tcp-listen 0.0.0.0:7791 --udp-forward 127.0.0.1:51820 
 - 0.0.0.0:7791 , server listen port
 - 127.0.0.1:51820, wireguard UDP listen port
 - tcp2udp, from https://github.com/mullvad/udp-over-tcp
