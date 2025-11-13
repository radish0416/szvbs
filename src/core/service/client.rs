#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::cipher::RsaCipher;
use crate::core::store::cache::{AppCache, LinkVntContext, VntContext};
use super::byte_rate_limiter::ByteRateLimiter;
use crate::error::*;
use crate::protocol::{NetPacket, Protocol};
use crate::ConfigInfo;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;

#[derive(Clone)]
pub struct ClientPacketHandler {
    cache: AppCache,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
    udp: Arc<UdpSocket>,
    ipturn_limiter: Option<Arc<Mutex<ByteRateLimiter>>>,
}

impl ClientPacketHandler {
    pub fn new(
        cache: AppCache,
        config: ConfigInfo,
        rsa_cipher: Option<RsaCipher>,
        udp: Arc<UdpSocket>,
    ) -> Self {
        let rate = config.ipturn_rate_limit_bytes;
        Self {
            cache,
            config,
            rsa_cipher,
            udp,
            ipturn_limiter: if rate > 0 {
                Some(Arc::new(Mutex::new(ByteRateLimiter::new(
                    rate as u64,
                    rate as f64,
                ))))
            } else {
                None
            },
        }
    }
}

impl ClientPacketHandler {
    pub async fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        context: &VntContext,
        net_packet: NetPacket<B>,
        _addr: SocketAddr,
    ) -> Result<()> {
        if let Some(context) = &context.link_context {
            self.handle0(context, net_packet).await
        } else {
            Err(Error::Disconnect)?
        }
    }
}

impl ClientPacketHandler {
    async fn broadcast<B: AsRef<[u8]> + AsMut<[u8]>>(&self, context: &LinkVntContext, udp_socket: &UdpSocket, net_packet: NetPacket<B>) {
        let is_encrypt = net_packet.is_encrypt();
        let source_ip = u32::from(net_packet.source());
        let x: Vec<_> = context
            .network_info
            .read()
            .clients
            .values()
            .filter(|v| {
                v.wireguard.is_none()
                    && v.online
                    && v.client_secret == is_encrypt
                    && v.virtual_ip != source_ip
            })
            .map(|v| (v.address, v.tcp_sender.clone()))
            .collect();
        for (peer_addr, peer_tcp_sender) in x {
            // IPturn 限流检查
            if net_packet.protocol() == Protocol::IpTurn && self.ipturn_limiter.is_some() {
                let size = net_packet.buffer().len() as u64;
                let mut limiter = self.ipturn_limiter.as_ref().unwrap().lock().unwrap();
                if !limiter.try_acquire_bytes(size) {
                    log::warn!("广播 IPturn限流拒绝，包大小 {} bytes 到 {}", size, peer_addr);
                    continue;
                }
            }
            send_one(udp_socket, peer_addr, peer_tcp_sender, &net_packet).await;
        }
    }
}

impl ClientPacketHandler {
    /// 转发到目标地址
    async fn handle0<B: AsRef<[u8]> + AsMut<[u8]>>(&self, context: &LinkVntContext, mut net_packet: NetPacket<B>) -> Result<()> {
        if net_packet.incr_ttl() > 1 {
            if self.config.check_finger {
                let finger = crate::cipher::Finger::new(&context.group);
                finger.check_finger(&net_packet)?;
            }
            let destination = net_packet.destination();
            if destination.is_broadcast() || self.config.broadcast == destination {
                //处理广播
                self.broadcast(context, &self.udp, net_packet).await;
            } else {
                let is_encrypt = net_packet.is_encrypt();
                let source_ip = u32::from(net_packet.source());
                let rs = context
                    .network_info
                    .read()
                    .clients
                    .get(&destination.into())
                    .filter(|v| {
                        v.wireguard.is_none()
                            && v.online
                            && v.client_secret == is_encrypt
                            && v.virtual_ip != source_ip
                    })
                    .map(|v| (v.address, v.tcp_sender.clone()));
                if let Some((peer_addr, peer_tcp_sender)) = rs {
                    // IPturn 限流检查
                    if net_packet.protocol() == Protocol::IpTurn && self.ipturn_limiter.is_some() {
                        let size = net_packet.buffer().len() as u64;
                        let mut limiter = self.ipturn_limiter.as_ref().unwrap().lock().unwrap();
                        if !limiter.try_acquire_bytes(size) {
                            log::warn!("IPturn限流拒绝，包大小 {} bytes", size);
                            return Ok(());
                        }
                    }
                    send_one(&self.udp, peer_addr, peer_tcp_sender, &net_packet).await;
                }
            }
        }
        Ok(())
    }
}

async fn send_one<B: AsRef<[u8]> + AsMut<[u8]>>(
    udp_socket: &UdpSocket,
    peer_addr: SocketAddr,
    peer_tcp_sender: Option<Sender<Vec<u8>>>,
    net_packet: &NetPacket<B>,
) {
    if let Some(sender) = &peer_tcp_sender {
        let _ = sender.send(net_packet.buffer().to_vec()).await;
    } else {
        let _ = udp_socket.send_to(net_packet.buffer(), peer_addr).await;
    }
}
