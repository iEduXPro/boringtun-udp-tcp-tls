// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;
pub mod api;
mod dev_lock;
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
pub mod peer;
use std::convert::{Infallible, TryFrom};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(target_os = "linux")]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

use std::collections::HashMap;
use std::io::{self, Write as _};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::x25519;
use allowed_ips::AllowedIps;
use parking_lot::Mutex;
use peer::{AllowedIP, Peer};
use poll::{EventPoll, EventRef, WaitResult};
use rand_core::{OsRng, RngCore};
use socket2::{Domain, Protocol, SockAddr, Type};
use tokio::net::TcpStream;
use tun::TunSocket;

use dev_lock::{Lock, LockReadGuard};

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const MAX_ITR: usize = 100; // Number of packets to handle per handler call

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    Socket(io::Error),
    #[error("{0}")]
    Bind(String),
    #[error("{0}")]
    FCntl(io::Error),
    #[error("{0}")]
    EventQueue(io::Error),
    #[error("{0}")]
    IOCtl(io::Error),
    #[error("{0}")]
    Connect(String),
    #[error("{0}")]
    SetSockOpt(String),
    #[error("Invalid tunnel name")]
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    #[error("{0}")]
    GetSockOpt(io::Error),
    #[error("{0}")]
    GetSockName(String),
    #[cfg(target_os = "linux")]
    #[error("{0}")]
    Timer(io::Error),
    #[error("iface read: {0}")]
    IfaceRead(io::Error),
    #[error("{0}")]
    DropPrivileges(String),
    #[error("API socket error: {0}")]
    ApiSocket(io::Error),
}

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and acquire it again
    Exit,     // Stop the loop
}

// Event handler function
type Handler = Box<dyn Fn(&mut LockReadGuard<Device>, &mut ThreadData) -> Action + Send + Sync>;

pub struct DeviceHandle { //用于管理设备和其相关线程
    device: Arc<Lock<Device>>, // The interface this handle owns //保存了设备对象，并且可以被多个线程安全共享，Arc 会在引用计数降到 0 时自动释放内存。
    threads: Vec<JoinHandle<()>>, //保存了所有与设备操作相关的线程句柄，允许管理这些线程的生命周期
}

#[derive(Debug, Clone, Copy)]
pub struct DeviceConfig {
    pub n_threads: usize,
    pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,
    #[cfg(target_os = "linux")]
    pub uapi_fd: i32,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            n_threads: 4,
            use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            #[cfg(target_os = "linux")]
            uapi_fd: -1,
        }
    }
}

pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    queue: Arc<EventPoll<Handler>>, //事件轮询队列，用于处理 I/O 事件。EventPoll 是事件轮询的实现，Handler 可能是与事件处理相关的函数或闭包。

    listen_port: u16,
    fwmark: Option<u32>,

    iface: Arc<TunSocket>,
    udp4: Option<socket2::Socket>,
    udp6: Option<socket2::Socket>,
    tcp4: Option<socket2::Socket>,    // add tcp4 
    tcp4_addr: Option<SockAddr>,
    tcp6: Option<socket2::Socket>,    // add tcp6
    yield_notice: Option<EventRef>,
    exit_notice: Option<EventRef>,
    is_tcp: bool,

    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    next_index: IndexLfsr,

    config: DeviceConfig,

    cleanup_paths: Vec<String>,

    mtu: AtomicUsize,

    rate_limiter: Option<Arc<RateLimiter>>,

    #[cfg(target_os = "linux")]
    uapi_fd: i32,
}

struct ThreadData {
    iface: Arc<TunSocket>,
    src_buf: [u8; MAX_UDP_SIZE],
    dst_buf: [u8; MAX_UDP_SIZE],
}

impl DeviceHandle {
    pub fn new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        let n_threads = config.n_threads;
        let mut wg_interface = Device::new(name, config)?;
        wg_interface.open_listen_socket(0)?; // Start listening on a random port

        let interface_lock = Arc::new(Lock::new(wg_interface));

        let mut threads = vec![];

        for i in 0..n_threads {
            threads.push({
                let dev = Arc::clone(&interface_lock);
                thread::spawn(move || DeviceHandle::event_loop(i, &dev))
            });
        }

        Ok(DeviceHandle {
            device: interface_lock,
            threads,
        })
    }

    pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            thread.join().unwrap();
        }
    }

    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(path);
        }
    }

    fn event_loop(_i: usize, device: &Lock<Device>) {
        #[cfg(target_os = "linux")]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: if _i == 0 || !device.read().config.use_multi_queue {
                // For the first thread use the original iface
                Arc::clone(&device.read().iface)
            } else {
                // For for the rest create a new iface queue
                let iface_local = Arc::new(
                    TunSocket::new(&device.read().iface.name().unwrap())
                        .unwrap()
                        .set_non_blocking()
                        .unwrap(),
                );

                device
                    .read()
                    .register_iface_handler(Arc::clone(&iface_local))
                    .ok();

                iface_local
            },
        };

        #[cfg(not(target_os = "linux"))]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: Arc::clone(&device.read().iface),
        };

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = device.read().uapi_fd;

        loop {
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let mut device_lock = device.read();
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock, &mut thread_local);
                        match action {
                            Action::Continue => {}
                            Action::Yield => break,
                            Action::Exit => {
                                device_lock.trigger_exit();
                                return;
                            }
                        }
                    }
                    WaitResult::EoF(handler) => {
                        if uapi_fd >= 0 && uapi_fd == handler.fd() {
                            device_lock.trigger_exit();
                            return;
                        }
                        handler.cancel();
                    }
                    WaitResult::Error(e) => tracing::error!(message = "Poll error", error = ?e),
                }
            }
        }
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

impl Device {
    fn next_index(&mut self) -> u32 {
        self.next_index.next()
    }

    fn remove_peer(&mut self, pub_key: &x25519::PublicKey) {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.lock();
                p.shutdown_endpoint(); // close open udp socket and free the closure
                self.peers_by_idx.remove(&p.index());
            }
            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            tracing::info!("Peer removed");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn update_peer(
        &mut self,
        pub_key: x25519::PublicKey,
        remove: bool,
        _replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        if remove {
            // Completely remove a peer
            return self.remove_peer(&pub_key);
        }

        // Update an existing peer
        if self.peers.get(&pub_key).is_some() {
            // We already have a peer, we need to merge the existing config into the newly created one
            panic!("Modifying existing peers is not yet supported. Remove and add again instead.");
        }

        let next_index = self.next_index();
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");

        let tunn = Tunn::new(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            keepalive,
            next_index,
            None,
        );

        let peer = Peer::new(tunn, next_index, endpoint, allowed_ips, preshared_key);

        let peer = Arc::new(Mutex::new(peer));
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        tracing::info!("Peer added");
    }

    pub fn new(name: &str, config: DeviceConfig) -> Result<Device, Error> {
        let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device
        let iface = Arc::new(TunSocket::new(name)?.set_non_blocking()?);
        let mtu = iface.mtu()?;

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = config.uapi_fd;

        let mut device = Device {
            queue: Arc::new(poll),
            iface,
            config,
            exit_notice: Default::default(),
            yield_notice: Default::default(),
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            udp4: Default::default(),
            udp6: Default::default(),
            tcp4: Default::default(),
            tcp4_addr: None,
            tcp6: Default::default(),
            is_tcp: true,
            cleanup_paths: Default::default(),
            mtu: AtomicUsize::new(mtu),
            rate_limiter: None,
            #[cfg(target_os = "linux")]
            uapi_fd,
        };

        if uapi_fd >= 0 {
            device.register_api_fd(uapi_fd)?;
        } else {
            device.register_api_handler()?;
        }
        device.register_iface_handler(Arc::clone(&device.iface))?;
        device.register_notifiers()?;
        device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                if name == "utun" {
                    std::fs::write(&name_file, device.iface.name().unwrap().as_bytes()).unwrap();
                    device.cleanup_paths.push(name_file);
                }
            }
        }

        Ok(device)
    }

    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        // Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        if let Some(s) = self.udp4.take() {
            unsafe {
                // This is safe because the event loop is not running yet
                self.queue.clear_event_by_fd(s.as_raw_fd())
            }
        };

        if let Some(s) = self.udp6.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }

        for peer in self.peers.values() {
            peer.lock().shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock4.set_reuse_address(true)?;
        udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        udp_sock4.set_nonblocking(true)?;

        if port == 0 {
            // Random port was assigned
            port = udp_sock4.local_addr()?.as_socket().unwrap().port();
        }

        let udp_sock6 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock6.set_reuse_address(true)?;
        udp_sock6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        udp_sock6.set_nonblocking(true)?;

        if !self.is_tcp {
            self.register_udp_handler(udp_sock4.try_clone().unwrap())?;
            self.register_udp_handler(udp_sock6.try_clone().unwrap())?;
            self.udp4 = Some(udp_sock4);
            self.udp6 = Some(udp_sock6);
            self.listen_port = port;
        }else {
            // 创建 TCP Socket
            eprintln!("1.创建 TCP Socket");
            let addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 22, 33), 7791);
            //let addr = SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 7791);
            let _addr = SockAddr::from(addr);
            self.tcp4_addr = Some(_addr.clone());
            let tcp_sock4 = socket2::Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
            tcp_sock4.set_reuse_address(true).unwrap();
            tcp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9981).into()).unwrap();
            tcp_sock4.set_nonblocking(false).unwrap();
            // Establish a connection to the remote address
            // Attempt to connect
            match tcp_sock4.connect(&_addr.clone()) {
                Ok(_) => {
                    eprintln!("2. 成功连接到远程地址");
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Connection in progress, wait for socket to become writable
                    eprintln!("2. Connection in progress, waiting...");
                }
                Err(e) => {
                    eprintln!("connect failed, {:?}", e);
                }
            }
            self.register_tcp_handler(tcp_sock4.try_clone().unwrap())?;
            self.tcp4 = Some(tcp_sock4);
        }
        eprintln!("open_listen_socket completed!!!");
        Ok(())
    }
    
    fn establish_tcp_connection(&mut self, peer: &Peer) -> Result<(), Error> {
        if let Some(addr) = peer.endpoint().addr {
            let stream = std::net::TcpStream::connect(addr)?;
            stream.set_nonblocking(true)?;
            //self.register_tcp_connection_handler(stream.try_clone()?, Arc::new(Mutex::new(peer)))?;
            //peer.set_tcp_connection(stream);
        }
        Ok(())
    }
    
    fn set_key(&mut self, private_key: x25519::StaticSecret) {
        let public_key = x25519::PublicKey::from(&private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            peer.lock().tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Some(Arc::clone(&rate_limiter)),
            )
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            sock.set_mark(mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            sock.set_mark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.values() {
            if let Some(ref sock) = peer.lock().endpoint().conn {
                sock.set_mark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_, _| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The exit event handler simply returns Action::Exit
            .new_notifier(Box::new(|_, _| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }

    fn register_timers(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;

        self.queue.new_periodic_event(
            // Execute the timed function of every peer in the list
            Box::new(|d, t| {
                let peer_map = &d.peers;
                let mut _tcp = d.tcp4.as_ref().expect("Not connected");
                /*
                let (udp4, udp6) = match (d.udp4.as_ref(), d.udp6.as_ref()) {
                    (Some(udp4), Some(udp6)) => (udp4, udp6),
                    _ => return Action::Continue,
                };
                 */
                // Go over each peer and invoke the timer function
                for peer in peer_map.values() {
                    let mut p = peer.lock();
                    let endpoint_addr = match p.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    match p.update_timers(&mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            p.shutdown_endpoint(); // close open udp socket
                        }
                        TunnResult::Err(e) => tracing::error!(message = "Timer error", error = ?e),
                        TunnResult::WriteToNetwork(packet) => {
                            tracing::error!("send to server {:?}", packet);
                            if d.is_tcp {
                                let _length = packet.len() as u16;
                                let mut result = Vec::with_capacity(packet.len() + 2);
                                result.extend_from_slice(&_length.to_be_bytes());
                                result.append(&mut packet.to_vec());
                                let _: Result<_, _> = _tcp.send(&result); //todo:
                            }else {
                                let (udp4, udp6) = match (d.udp4.as_ref(), d.udp6.as_ref()) {
                                    (Some(udp4), Some(udp6)) => (udp4, udp6),
                                    _ => return Action::Continue,
                                };
                                match endpoint_addr {
                                    SocketAddr::V4(_) => {
                                        udp4.send_to(packet, &endpoint_addr.into()).ok()
                                    }
                                    SocketAddr::V6(_) => {
                                        udp6.send_to(packet, &endpoint_addr.into()).ok()
                                    }
                                };
                            }
                        }
                        _ => panic!("Unexpected result from update_timers"),
                    };
                }
                Action::Continue
            }),
            std::time::Duration::from_millis(250),
        )?;
        Ok(())
    }

    pub(crate) fn trigger_yield(&self) {
        self.queue
            .trigger_notification(self.yield_notice.as_ref().unwrap())
    }

    pub(crate) fn trigger_exit(&self) {
        self.queue
            .trigger_notification(self.exit_notice.as_ref().unwrap())
    }

    pub(crate) fn cancel_yield(&self) {
        self.queue
            .stop_notification(self.yield_notice.as_ref().unwrap())
    }

    fn register_tcp_handler(&self, tcp: socket2::Socket) -> Result<(), Error> {
        self.queue.new_event(
            tcp.as_raw_fd(), 
            Box::new(move |d, t| {
                // Handler that handles anonymous packets over UDP
                let mut iter = MAX_ITR;
                let (private_key, public_key) = d.key_pair.as_ref().expect("Key not set");
                let rate_limiter = d.rate_limiter.as_ref().unwrap();
                let src_buf = unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
                while let Ok((packet_len, _)) = tcp.recv_from(src_buf) {

                    let _addr = d.tcp4_addr.clone().unwrap();
                    let packet = &t.src_buf[2..packet_len];
                    tracing::debug!("me<-wg:{:?}", packet_len-2);
                    tracing::debug!("me<-wg:{:?}", packet);
                    let parsed_packet = match rate_limiter.verify_packet(
                        Some(SocketAddr::V4("127.0.0.1:8765".parse().unwrap()).ip()),
                        packet,
                        &mut t.dst_buf,
                    ) {
                        Ok(packet) => packet,
                        Err(TunnResult::WriteToNetwork(cookie)) => {
                            let _length = cookie.len() as u16;
                            let mut result = Vec::with_capacity(cookie.len() + 2);
                            result.extend_from_slice(&_length.to_be_bytes());
                            result.append(&mut cookie.to_vec());

                            tracing::error!("me->wg {}", &result.len());
                            tracing::error!("me->wg {:?}", result);  

                            let _: Result<_, _> = tcp.send(&result); //todo:
                            continue;
                        }
                        Err(_) => continue,
                    };

                    let peer = match &parsed_packet {
                        Packet::HandshakeInit(p) => {
                            parse_handshake_anon(private_key, public_key, p)
                                .ok()
                                .and_then(|hh| {
                                    d.peers.get(&x25519::PublicKey::from(hh.peer_static_public))
                                })
                        }
                        Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                    };

                    let peer = match peer {
                        None => continue,
                        Some(peer) => peer,
                    };

                    let mut p = peer.lock();

                    // We found a peer, use it to decapsulate the message+
                    let mut flush = false; // Are there packets to send from the queue?
                    match p
                        .tunnel
                        .handle_verified_packet(parsed_packet, &mut t.dst_buf[..])
                    {
                        TunnResult::Done => {}
                        TunnResult::Err(_) => continue,
                        TunnResult::WriteToNetwork(packet) => {     //数据包处理：b. 发送响应包：
                            let _length = packet.len() as u16;
                            let mut result = Vec::with_capacity(packet.len() + 2);
                            result.extend_from_slice(&_length.to_be_bytes());
                            result.append(&mut packet.to_vec());

                            tracing::error!("me->wg {}", &result.len());
                            tracing::error!("me->wg {:?}", result);                            
                            flush = true;
                            let _: Result<_, _> = tcp.send(&result);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                t.iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                t.iface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        tracing::debug!("Flush pending queue");
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            let _length = packet.len() as u16;
                            let mut result = Vec::with_capacity(packet.len() + 2);
                            result.extend_from_slice(&_length.to_be_bytes());
                            result.append(&mut packet.to_vec());

                            tracing::error!("me->wg lenght {:?}", &result.len());
                            tracing::error!("me->wg {:?}", result);
                            let _: Result<_, _> = tcp.send(&result);
                        }
                    }

                    // This packet was OK, that means we want to create a connected socket for this peer
                    let addr = _addr.as_socket().unwrap();
                    let ip_addr = addr.ip();
                    p.set_endpoint(addr);
                    if d.config.use_connected_socket {
                        if let Ok(sock) = p.connect_endpoint(d.listen_port, d.fwmark) {
                            d.register_tcp_conn_handler(Arc::clone(peer), sock, ip_addr)
                                .unwrap();
                        }
                    }
                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
                }
            )
        )?;
        Ok(())
    }

    fn register_tcp_conn_handler(
        &self,
        peer: Arc<Mutex<Peer>>,
        tcp: socket2::Socket,
        peer_addr: IpAddr,
    ) -> Result<(), Error> {
        self.queue.new_event(
            tcp.as_raw_fd(),
            Box::new(move |_, t| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let iface = &t.iface;
                let mut iter = MAX_ITR;

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let src_buf =
                    unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
                while let Ok(read_bytes) = tcp.recv(src_buf) {
                    let mut flush = false;
                    let mut p = peer.lock();
                    match p.tunnel.decapsulate(
                        Some(peer_addr),
                        &t.src_buf[..read_bytes],
                        &mut t.dst_buf[..],
                    ) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => eprintln!("Decapsulate error {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            let _length = packet.len() as u16;
                            let mut result = Vec::with_capacity(packet.len() + 2);
                            result.extend_from_slice(&_length.to_be_bytes());
                            result.append(&mut packet.to_vec());

                            tracing::error!("me->wg lenght {:?}", &result.len());
                            tracing::error!("me->wg {:?}", result);
                            let _: Result<_, _> = tcp.send(&result);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                iface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        tracing::debug!("Flush pending queue@register_conn_handler");
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            let _length = packet.len() as u16;
                            let mut result = Vec::with_capacity(packet.len() + 2);
                            result.extend_from_slice(&_length.to_be_bytes());
                            result.append(&mut packet.to_vec());

                            tracing::error!("me->wg lenght {:?}", &result.len());
                            tracing::error!("me->wg {:?}", result);
                            let _: Result<_, _> = tcp.send(&result);
                        }
                    }
                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }
    // 处理接收到的udp数据包
    fn register_udp_handler(&self, udp: socket2::Socket) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // Handler that handles anonymous packets over UDP
                let mut iter = MAX_ITR;
                let (private_key, public_key) = d.key_pair.as_ref().expect("Key not set");

                let rate_limiter = d.rate_limiter.as_ref().unwrap();

                // Loop while we have packets on the anonymous connection

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let src_buf = unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
                while let Ok((packet_len, addr)) = udp.recv_from(src_buf) { //数据包处理：a. 接收握手初始化包和数据包？？
                    let packet = &t.src_buf[..packet_len];
                    // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
                    tracing::debug!("receive bytes:{:?} from {:?}", packet, addr);
                    let parsed_packet = match rate_limiter.verify_packet(
                        Some(addr.as_socket().unwrap().ip()),
                        packet,
                        &mut t.dst_buf,
                    ) {
                        Ok(packet) => packet,
                        Err(TunnResult::WriteToNetwork(cookie)) => {
                            tracing::error!("me->wg {:?}", cookie);
                            let _: Result<_, _> = udp.send_to(cookie, &addr);
                            continue;
                        }
                        Err(_) => continue,
                    };

                    let peer = match &parsed_packet {
                        Packet::HandshakeInit(p) => {
                            parse_handshake_anon(private_key, public_key, p)
                                .ok()
                                .and_then(|hh| {
                                    d.peers.get(&x25519::PublicKey::from(hh.peer_static_public))
                                })
                        }
                        Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                    };

                    let peer = match peer {
                        None => continue,
                        Some(peer) => peer,
                    };

                    let mut p = peer.lock();

                    // We found a peer, use it to decapsulate the message+
                    let mut flush = false; // Are there packets to send from the queue?
                    match p
                        .tunnel
                        .handle_verified_packet(parsed_packet, &mut t.dst_buf[..])
                    {
                        TunnResult::Done => {}
                        TunnResult::Err(_) => continue,
                        TunnResult::WriteToNetwork(packet) => {     //数据包处理：b. 发送响应包：                            
                            flush = true;
                            tracing::error!("me->wg {:?}", packet);
                            let _: Result<_, _> = udp.send_to(packet, &addr);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                t.iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                t.iface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        tracing::debug!("Flush pending queue");
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            tracing::error!("me->wg {:?}", packet);
                            let _: Result<_, _> = udp.send_to(packet, &addr);
                        }
                    }

                    // This packet was OK, that means we want to create a connected socket for this peer
                    let addr = addr.as_socket().unwrap();
                    let ip_addr = addr.ip();
                    p.set_endpoint(addr);
                    if d.config.use_connected_socket {
                        if let Ok(sock) = p.connect_endpoint(d.listen_port, d.fwmark) {
                            d.register_conn_handler(Arc::clone(peer), sock, ip_addr)
                                .unwrap();
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }
    //处理从对等方通过 UDP socket 发来的封装流量，对其进行解封装，
    //并将解封装后的数据发送到虚拟网络接口或将其重新封装后通过网络发送。
    //数据包处理：c. 处理已知peer的通信：
    //在Device::register_conn_handler中，为已知的peer创建专用的connected socket，提高通信效率。
    fn register_conn_handler(
        &self,
        peer: Arc<Mutex<Peer>>,
        udp: socket2::Socket,
        peer_addr: IpAddr,
    ) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |_, t| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let iface = &t.iface;
                let mut iter = MAX_ITR;

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let src_buf =
                    unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
                while let Ok(read_bytes) = udp.recv(src_buf) {
                    let mut flush = false;
                    let mut p = peer.lock();
                    match p.tunnel.decapsulate(
                        Some(peer_addr),
                        &t.src_buf[..read_bytes],
                        &mut t.dst_buf[..],
                    ) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => eprintln!("Decapsulate error {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            tracing::error!("me->wg {:?}", packet);
                            flush = true;
                            let _: Result<_, _> = udp.send(packet);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                iface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        tracing::debug!("Flush pending queue@register_conn_handler");
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            tracing::error!("me->wg {:?}", packet);
                            let _: Result<_, _> = udp.send(packet);
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }
    // 功能是在虚拟网卡上监听从本地发出的 IP 数据包，解析目的地址，找到对应的 WireGuard 对等方，
    // 并将数据包封装成 WireGuard 流量后通过 UDP socket 发送给对等方。
    // 这是 WireGuard 处理虚拟网络接口流量的关键环节
    fn register_iface_handler(&self, iface: Arc<TunSocket>) -> Result<(), Error> {
        eprintln!("register_iface_handler");
        self.queue.new_event(
            iface.as_raw_fd(),
            Box::new(move |d, t| {
                // The iface_handler handles packets received from the WireGuard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                let mtu = d.mtu.load(Ordering::Relaxed);

                let peers = &d.peers_by_ip;
                for _ in 0..MAX_ITR {
                    let src = match iface.read(&mut t.src_buf[..mtu]) {
                        Ok(src) => src,
                        Err(Error::IfaceRead(e)) => {
                            let ek = e.kind();
                            if ek == io::ErrorKind::Interrupted || ek == io::ErrorKind::WouldBlock {
                                break;
                            }
                            eprintln!("Fatal read error on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                        Err(e) => {
                            eprintln!("Unexpected error on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                    };

                    let dst_addr = match Tunn::dst_address(src) {
                        Some(addr) => addr,
                        None => continue,
                    };

                    let mut peer = match peers.find(dst_addr) {
                        Some(peer) => peer.lock(),
                        None => continue,
                    };
                    // send to server
                    match peer.tunnel.encapsulate(src, &mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => {
                            tracing::error!(message = "Encapsulate error", error = ?e)
                        }
                        TunnResult::WriteToNetwork(packet) => { // tcp send to server
                            if d.is_tcp {
                                let mut _tcp = d.tcp4.as_ref().expect("Not connected");

                                let _length = packet.len() as u16;
                                let mut result = Vec::with_capacity(packet.len() + 2);
                                result.extend_from_slice(&_length.to_be_bytes());
                                result.append(&mut packet.to_vec());
                                tracing::error!("me->wg {}", _length);
                                tracing::error!("me->wg {:?}", result);
                                match _tcp.write_all(&result){
                                    Ok(_) => {
                                    },
                                    Err(e) => {
                                        tracing::error!(message = "Encapsulate error", error = ?e);
                                    },
                                }
                            }else { // udp send to server
                                let udp4 = d.udp4.as_ref().expect("Not connected");
                                let udp6 = d.udp6.as_ref().expect("Not connected");
                                tracing::error!("me->wg {:?}", packet);
                                let mut endpoint = peer.endpoint_mut();
                                if let Some(conn) = endpoint.conn.as_mut() {
                                    // Prefer to send using the connected socket
                                    
                                    let _: Result<_, _> = conn.write(packet);
                                } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                                    let _: Result<_, _> = udp4.send_to(packet, &addr.into());
                                } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                                    let _: Result<_, _> = udp6.send_to(packet, &addr.into());
                                } else {
                                    tracing::error!("No endpoint");
                                }
                            }
                        }
                        _ => panic!("Unexpected result from encapsulate"),
                    };
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }
}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_index() -> u32 {
        const LFSR_MAX: u32 = 0xffffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence
    fn next(&mut self) -> u32 {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0xd80000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        assert!(self.lfsr != self.initial, "Too many peers created");
        value ^ self.mask
    }
}

impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_index();
        IndexLfsr {
            initial: seed,
            lfsr: seed,
            mask: Self::random_index(),
        }
    }
}


/*
WireGuard Implementation
│
├── DeviceHandle                            //管理Device和相关线程的生命周期。
│   ├── new()
│   ├── wait()
│   ├── clean()
│   └── event_loop()                        //函数实现了主事件循环,处理各种网络事件和定时器。
│
├── Device                                  //包含WireGuard设备的核心状态,如密钥、网络接口、对等点列表等。
│   ├── Structure
│   │   ├── key_pair
│   │   ├── queue (EventPoll)
│   │   ├── iface (TunSocket)
│   │   ├── udp4/udp6 sockets               //其中的 udp4 和 udp6 套接字（sockets）用于与网络进行通信
│   │   ├── tcp4/tcp6 sockets
│   │   └── peers (HashMap)
│   │
│   ├── Initialization
│   │   ├── new()
│   │   ├── open_listen_socket()
│   │   └── register_handlers()
│   │
│   ├── Peer Management
│   │   ├── update_peer()
│   │   ├── remove_peer()
│   │   └── clear_peers()
│   │
│   ├── Key Management
│   │   └── set_key()                       //方法设置设备的私钥和公钥,并更新所有对等点的加密状态。
│   │
│   ├── Event Handlers
│   │   ├── register_udp_handler()          //方法注册了处理UDP数据包的回调函数。它负责接收、验证和解封装来自对等点的数据包。
│   │   ├── register_conn_handler()         //方法处理已建立连接的UDP socket,提高了数据处理效率。
│   │   ├── register_iface_handler()        //方法处理来自虚拟网络接口的数据包,将它们封装并发送给相应的对等点。
│   │   └── register_tcp_handler()
│   │
│   └── Utilities
│       ├── trigger_yield()
│       ├── trigger_exit()
│       └── cancel_yield()
│
└── Peer                                    //表示一个WireGuard对等点,包含其隧道状态、端点信息等。
    ├── Structure
    │   ├── tunnel (Tunn)
    │   ├── endpoint
    │   └── allowed_ips
    │
    ├── Methods
    │   ├── new()
    │   ├── update_timers()
    │   ├── set_endpoint()
    │   └── is_allowed_ip()
    │
    └── Connection Management
        └── connect_endpoint()
*/