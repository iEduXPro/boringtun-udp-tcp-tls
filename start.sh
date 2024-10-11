sudo wg set utun6 listen-port 9989 private-key ./private.key peer qHaIfS7u47/U1AuigBDhOv/p/t6Gy+XKSUdYnPIEKDA= preshared-key ./preshared.key endpoint 47.128.76.20:62829 allowed-ips 0.0.0.0/0 persistent-keepalive 25

sudo ifconfig utun6 inet 10.10.0.2/24 10.10.0.2 alias && sudo ifconfig utun6 up && sudo route -q -n add -inet 0.0.0.0/1 -interface utun6