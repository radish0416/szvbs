#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::cipher::RsaCipher;
use crate::core::store::cache::{AppCache, LinkVntContext, VntContext};
use crate::error::*;
use crate::protocol::{NetPacket, Protocol};
use crate::ConfigInfo;
use super::rate_limiter::ConcurrentByteRateLimiter;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

#[derive(Clone)]
pub struct ClientPacketHandler {
    cache: AppCache,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
    udp: Arc<UdpSocket>,
    blocked: bool,
    limiter: Option<Arc<ConcurrentByteRateLimiter>>,
}

impl ClientPacketHandler {
    pub fn new(
        cache: AppCache,
        config: ConfigInfo,
        rsa_cipher: Option<RsaCipher>,
        udp: Arc<UdpSocket>,
    ) -> Self {
        let (blocked, limiter) = match config.rate_limit {
            None => (false, None),
            Some(rate) => {
                if rate == 0 {
                    (true, None)
                } else {
                    (false, Some(Arc::new(ConcurrentByteRateLimiter::new(rate, rate as f64))))
                }
            }
        };
        Self {
            cache,
            config,
            rsa_cipher,
            udp,
            blocked,
            limiter,
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
    /// 转发到目标地址
    async fn handle0<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        context: &LinkVntContext,
        mut net_packet: NetPacket<B>,
    ) -> Result<()> {
        if net_packet.incr_ttl() > 1 {
            if self.config.check_finger {
                let finger = crate::cipher::Finger::new(&context.group);
                finger.check_finger(&net_packet)?;
            }
            let destination = net_packet.destination();
            let is_ip_turn = net_packet.protocol() == Protocol::IpTurn;
            if is_ip_turn {
                if self.blocked {
                    return Ok(());
                }
                if let Some(ref limiter) = self.limiter {
                    let size = net_packet.data_len() as u64;
                    while !limiter.try_acquire_bytes(size) {
                        sleep(Duration::from_millis(1)).await;
                    }
                }
            }
            if destination.is_broadcast() || self.config.broadcast == destination {
                //处理广播
                broadcast(context, &self.udp, net_packet, &self.blocked, &self.limiter).await;
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
                    send_one(&self.udp, peer_addr, peer_tcp_sender, &net_packet).await;
                }
            }
        }
        Ok(())
    }
}

async fn broadcast<B: AsRef<[u8]>>(
    context: &LinkVntContext,
    udp_socket: &UdpSocket,
    net_packet: NetPacket<B>,
    blocked: &bool,
    limiter: &Option<Arc<ConcurrentByteRateLimiter>>,
) {
    if *blocked || net_packet.protocol() != Protocol::IpTurn {
        return;
    }
    let is_encrypt = net_packet.is_encrypt();
    let source_ip = u32::from(net_packet.source());
    let size = net_packet.data_len() as u64;
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
        if let Some(ref l) = limiter {
            while !l.try_acquire_bytes(size) {
                sleep(Duration::from_millis(1)).await;
            }
        }
        send_one(udp_socket, peer_addr, peer_tcp_sender, &net_packet).await;
    }
}

async fn send_one<B: AsRef<[u8]>>(
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
