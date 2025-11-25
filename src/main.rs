use aes_gcm::aead::rand_core::RngCore;
use anyhow::{anyhow, Context};
use base64::engine::general_purpose;
use base64::Engine;
use boringtun::x25519::{PublicKey, StaticSecret};
use clap::Parser;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use serde::Deserialize;
use toml;
use std::fs;  // 添加到顶部use


#[cfg(feature = "web")]
#[derive(Deserialize, Clone, Debug)]
struct WebConfig {
    web_port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
struct ConfigFile {
    host: Option<String>,
    port: Option<u16>,
    white_token: Option<Vec<String>>,
    gateway: Option<String>,
    netmask: Option<String>,
    finger: Option<bool>,
    log_path: Option<String>,
    wg_secret_key: Option<String>,
    rate_limit: Option<u64>,
    #[cfg(feature = "web")]
    web: Option<WebConfig>,
}

use crate::cipher::RsaCipher;

mod cipher;
mod core;
mod error;
mod generated_serial_number;
mod proto;
mod protocol;

pub const VNT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 默认网关信息
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 26, 0, 1);
const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

#[derive(Parser, Debug, Clone)]
#[command(version)]
pub struct StartArgs {
    /// 指定服务监听的IP地址，默认监听所有地址
    #[arg(long)]
    host: Option<String>,
    /// 指定端口，默认29872
    #[arg(short, long)]
    port: Option<u16>,
    /// token白名单，例如 --white-token 1234 --white-token 123
    #[arg(short, long)]
    white_token: Option<Vec<String>>,
    /// 网关，例如 --gateway 10.10.0.1
    #[arg(short, long)]
    gateway: Option<String>,
    /// 子网掩码，例如 --netmask 255.255.255.0
    #[arg(short = 'm', long)]
    netmask: Option<String>,
    ///开启指纹校验，开启后只会转发指纹正确的客户端数据包，增强安全性，这会损失一部分性能
    #[arg(short, long, default_value_t = false)]
    finger: bool,
    /// log路径，默认为当前程序路径，为/dev/null时表示不输出log
    #[arg(short, long)]
    log_path: Option<String>,
    #[cfg(feature = "web")]
    ///web后台端口，默认29870，如果设置为0则表示不启动web后台
    #[arg(short = 'P', long)]
    web_port: Option<u16>,
    #[cfg(feature = "web")]
    /// web后台用户名，默认为admin
    #[arg(short = 'U', long)]
    username: Option<String>,
    #[cfg(feature = "web")]
    /// web后台用户密码，默认为admin
    #[arg(short = 'W', long)]
    password: Option<String>,
    /// wg私钥，使用base64编码
    #[arg(long = "wg")]
    wg_secret_key: Option<String>,
    /// 速率限制（字节/秒），0表示全部限制，默认无
    #[arg(long)]
    rate_limit: Option<u64>,
    /// 配置文件路径，例如 --conf config.toml
    #[arg(long)]
    conf: Option<PathBuf>,
     /// Token白名单文件路径，每行一个token，例如 --token tokens.txt
     #[arg(long)]
     token: Option<PathBuf>,
}

#[derive(Clone)]
pub struct ConfigInfo {
    pub port: u16,
    pub white_token: Option<HashSet<String>>,
    pub gateway: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub check_finger: bool,
    #[cfg(feature = "web")]
    pub username: String,
    #[cfg(feature = "web")]
    pub password: String,
    pub wg_secret_key: StaticSecret,
    pub wg_public_key: PublicKey,
    pub rate_limit: Option<u64>,
}
impl Debug for ConfigInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigInfo")
            .field("port", &self.port)
            .field("white_token", &self.white_token)
            .field("gateway", &self.gateway)
            .field("broadcast", &self.broadcast)
            .field("netmask", &self.netmask)
            .field("check_finger", &self.check_finger)
            .field(
                "wg_secret_key",
                &general_purpose::STANDARD.encode(&self.wg_secret_key),
            )
            .field(
                "wg_public_key",
                &general_purpose::STANDARD.encode(&self.wg_public_key),
            )
            .finish()
    }
}

fn log_init(root_path: PathBuf, log_path: Option<String>) {
    let log_path = match log_path {
        None => root_path.join("log"),
        Some(log_path) => {
            if &log_path == "/dev/null" {
                return;
            }
            PathBuf::from(log_path)
        }
    };
    if !log_path.exists() {
        let _ = std::fs::create_dir(&log_path);
    }

    let log_config = log_path.join("log4rs.yaml");
    if !log_config.exists() {
        if let Ok(mut f) = std::fs::File::create(&log_config) {
            let log_path = log_path.to_str().unwrap();
            let c = format!(
                "refresh_rate: 30 seconds
appenders:
  rolling_file:
    kind: rolling_file
    path: {}/iotnet.log
    append: true
    encoder:
      pattern: \"{{d}} [{{f}}:{{L}}] {{h({{l}})}} {{M}}:{{m}}{{n}}\"
    policy:
      kind: compound
      trigger:
        kind: size
        limit: 10 mb
      roller:
        kind: fixed_window
        pattern: {}/iotnet.{{}}.log
        base: 1
        count: 5

root:
  level: info
  appenders:
    - rolling_file",
                log_path, log_path
            );
            let _ = f.write_all(c.as_bytes());
        }
    }
    let _ = log4rs::init_file(log_config, Default::default());
}

pub fn app_root() -> PathBuf {
    match std::env::current_exe() {
        Ok(path) => {
            if let Some(v) = path.as_path().parent() {
                v.to_path_buf()
            } else {
                log::warn!("current_exe parent none:{:?}", path);
                PathBuf::new()
            }
        }
        Err(e) => {
            log::warn!("current_exe err:{:?}", e);
            PathBuf::new()
        }
    }
}

#[tokio::main]
async fn main() {
    println!("version: {}", VNT_VERSION);
    println!("Serial: {}", generated_serial_number::SERIAL_NUMBER);
    let args = StartArgs::parse();

    // 加载配置文件
    let config_opt: Option<ConfigFile> = match args.conf.as_ref() {
        Some(path) => {
            match std::fs::read_to_string(path) {
                Ok(content) => match toml::from_str::<ConfigFile>(&content) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        eprintln!("解析TOML配置文件失败: {}，路径: {}", e, path.display());
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("读取配置文件失败: {}，路径: {}", e, path.display());
                    std::process::exit(1);
                }
            }
        },
        None => None,
    };

    let root_path = app_root();
    let effective_log_path = args.log_path.or(config_opt.as_ref().and_then(|c| c.log_path.clone()));
    log_init(root_path.clone(), effective_log_path);
    
    // 有效端口
    let port = args.port.or(config_opt.as_ref().and_then(|c| c.port)).unwrap_or(29872);
    let host = args.host.or(config_opt.as_ref().and_then(|c| c.host.clone()));
    
    #[cfg(feature = "web")]
    let web_port = {
        let wp = args.web_port
            .or(config_opt.as_ref().and_then(|c| c.web.as_ref().and_then(|w| w.web_port)))
            .unwrap_or(29870);
        println!("端口: {}", port);
        if wp != 0 {
            println!("web端口: {}", wp);
            if wp == port {
                panic!("web-port == port");
            }
        } else {
            println!("不启用web后台")
        }
        wp
    };

    #[cfg(feature = "web")]
    let username = args.username
        .or(config_opt.as_ref().and_then(|c| c.web.as_ref().and_then(|w| w.username.clone())))
        .unwrap_or_else(|| "admin".into());

    #[cfg(feature = "web")]
    let password = args.password
        .or(config_opt.as_ref().and_then(|c| c.web.as_ref().and_then(|w| w.password.clone())))
        .unwrap_or_else(|| "admin".into());

    // 白名单
    // let white_token_opt = args.white_token.or(config_opt.as_ref().and_then(|c| c.white_token.clone()));
    // let white_token = white_token_opt.map(|v| HashSet::from_iter(v.into_iter()));
    // println!("token白名单: {:?}", white_token);

    // 白名单 - 支持文件读取
    let mut white_token_set: HashSet<String> = HashSet::new();

    // 1. 命令行 --white-token 优先
    if let Some(tokens) = &args.white_token {
       white_token_set.extend(tokens.iter().cloned());
    }
    // 2. --token 文件
    if let Some(path) = &args.token {
        match fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        white_token_set.insert(trimmed.to_string());
                    }
                }
                if !white_token_set.is_empty() {
                    println!("从文件加载token白名单: {} 个", white_token_set.len());
                }
            }
            Err(e) => {
                eprintln!("Token文件读取失败: {}，路径: {}，继续使用其他白名单", e, path.display());
            }
        }
    }
    // 3. config.toml fallback（如果命令行和文件为空）
       if white_token_set.is_empty() {
           if let Some(config) = &config_opt {
               if let Some(tokens) = &config.white_token {
                   white_token_set.extend(tokens.iter().cloned());
               }
           }
       }

       let white_token = if white_token_set.is_empty() { None } else { Some(white_token_set) };
       println!("最终token白名单: {:?}", white_token);

    // 网关
    let gateway_str = args.gateway.or(config_opt.as_ref().and_then(|c| c.gateway.clone()));
    let gateway = if let Some(g_str) = gateway_str {
        match g_str.parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(e) => {
                log::error!("网关错误，必须为有效的ipv4地址 gateway={},e={}", g_str, e);
                panic!("网关错误，必须为有效的ipv4地址")
            }
        }
    } else {
        GATEWAY
    };
    println!("网关: {:?}", gateway);
    if gateway.is_unspecified() {
        println!("网关地址无效");
        log::error!("网关错误，必须为有效的ipv4地址 gateway={}", gateway);
        return;
    }
    if gateway.is_broadcast() {
        println!("网关错误，不能为广播地址");
        log::error!("网关错误，不能为广播地址 gateway={}", gateway);
        return;
    }
    if gateway.is_multicast() {
        println!("网关错误，不能为组播地址");
        log::error!("网关错误，不能为组播地址 gateway={}", gateway);
        return;
    }
    if !gateway.is_private() {
        println!(
            "Warning 不是一个私有地址：{:?}，将有可能和公网ip冲突",
            gateway
        );
        log::warn!("网关错误，不是一个私有地址 gateway={}", gateway);
    }

    // 子网掩码
    let netmask_str = args.netmask.or(config_opt.as_ref().and_then(|c| c.netmask.clone()));
    let netmask = if let Some(n_str) = netmask_str {
        match n_str.parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(e) => {
                log::error!(
                    "子网掩码错误，必须为有效的ipv4地址 netmask={},e={}",
                    n_str,
                    e
                );
                panic!("子网掩码错误，必须为有效的ipv4地址")
            }
        }
    } else {
        NETMASK
    };
    println!("子网掩码: {:?}", netmask);
    if netmask.is_broadcast()
        || netmask.is_unspecified()
        || !(!u32::from_be_bytes(netmask.octets()) + 1).is_power_of_two()
    {
        println!("子网掩码错误");
        log::error!("子网掩码错误 netmask={}", netmask);
        return;
    }

    let broadcast = (!u32::from_be_bytes(netmask.octets())) | u32::from_be_bytes(gateway.octets());
    let broadcast = Ipv4Addr::from(broadcast);

    // 指纹校验
    let check_finger = if args.finger {
        true
    } else {
        config_opt.as_ref().map_or(false, |c| c.finger.unwrap_or(false))
    };
    if check_finger {
        println!("转发校验数据指纹，客户端必须增加--finger参数");
    }

    // WG密钥 - 添加fallback逻辑
    let wg_sk_str = args.wg_secret_key.or(config_opt.as_ref().and_then(|c| c.wg_secret_key.clone()));
    let wg_secret_key_bytes: [u8; 32] = if let Some(sk_str) = wg_sk_str {
        match general_purpose::STANDARD.decode(&sk_str.trim()) {  // trim()去除可能的空格
            Ok(decoded) => {
                if decoded.len() == 32 {
                    match decoded.try_into() {
                        Ok(key) => key,
                        Err(_) => {
                            eprintln!("WG私钥长度无效，使用随机生成: {}", sk_str);
                            let mut key = [0u8; 32];
                            rand::thread_rng().fill_bytes(&mut key);
                            key
                        }
                    }
                } else {
                    eprintln!("WG私钥解码长度不是32字节 (实际: {}), 使用随机生成: {}", decoded.len(), sk_str);
                    let mut key = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut key);
                    key
                }
            }
            Err(e) => {
                eprintln!("WG私钥Base64解码失败: {}, 使用随机生成: {}", e, sk_str);
                let mut key = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut key);
                key
            }
        }
    } else {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    };
    let wg_secret_key = boringtun::x25519::StaticSecret::from(wg_secret_key_bytes);
    let wg_public_key = boringtun::x25519::PublicKey::from(&wg_secret_key);

    // 速率限制
    let rate_limit = args.rate_limit.or(config_opt.as_ref().and_then(|c| c.rate_limit));

    let config = ConfigInfo {
        port,
        white_token,
        gateway,
        broadcast,
        netmask,
        check_finger,
        #[cfg(feature = "web")]
        username,
        #[cfg(feature = "web")]
        password,
        wg_secret_key,
        wg_public_key,
        rate_limit,
    };

    let rsa = match RsaCipher::new(root_path) {
        Ok(rsa) => {
            println!("密钥指纹: {}", rsa.finger());
            Some(rsa)
        }
        Err(e) => {
            log::error!("获取密钥错误：{:?}", e);
            panic!("获取密钥错误:{}", e);
        }
    };
    log::info!("config:{:?}", config);
    let udp = create_udp(port, host.as_deref()).unwrap();
    log::info!("监听host:{:?},监听udp端口: {:?}",host, port);
    println!("监听host:{:?},监听udp端口: {:?}", host, port);
    let tcp = create_tcp(port, host.as_deref()).unwrap();
    log::info!("监听host:{:?},tcp/ws端口: {:?}",host, port);
    println!("监听host:{:?},监听tcp/ws端口: {:?}",host, port);
    #[cfg(feature = "web")]
    let http = if web_port != 0 {
        let http = create_tcp(web_port, host.as_deref()).unwrap();
        log::info!("监听http端口: {:?}", web_port);
        println!("监听http端口: {:?}", web_port);
        Some(http)
    } else {
        None
    };
    let config = config.clone();
    if let Err(e) = core::start(
        udp,
        tcp,
        #[cfg(feature = "web")]
        http,
        config,
        rsa,
    )
    .await
    {
        log::error!("{:?}", e)
    }
}

fn create_tcp(port: u16, host: Option<&str>) -> io::Result<std::net::TcpListener> {
    let address_str = match host {
        Some(h) => format!("{}:{}", h, port),
        None => format!("[::]:{}", port),
    };
    let address: std::net::SocketAddr = address_str.parse().unwrap();
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = io_convert(
        socket2::Socket::new(domain, socket2::Type::STREAM, None),
        |e| format!("new STREAM {:?}", e),
    )?;
    if domain == socket2::Domain::IPV6 {
        io_convert(socket.set_only_v6(false), |e| {
            format!("set_only_v6 {:?}", e)
        })?;
    }
    io_convert(socket.set_reuse_address(true), |e| {
        format!("set_reuse_address {:?}", e)
    })?;
    io_convert(socket.set_nonblocking(true), |e| {
        format!("set_nonblocking {:?}", e)
    })?;
    io_convert(socket.bind(&address.into()), |e| {
        format!("bind {:?},{:?}", address, e)
    })?;
    io_convert(socket.listen(1024), |e| {
        format!("listen {:?},{:?}", address, e)
    })?;
    Ok(socket.into())
}

fn create_udp(port: u16, host: Option<&str>) -> io::Result<std::net::UdpSocket> {
    let address_str = match host {
        Some(h) => format!("{}:{}", h, port),
        None => format!("[::]:{}", port),
    };
    let address: std::net::SocketAddr = address_str.parse().unwrap();
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = io_convert(
        socket2::Socket::new(domain, socket2::Type::DGRAM, None),
        |e| format!("new DGRAM {:?}", e),
    )?;
    if domain == socket2::Domain::IPV6 {
        io_convert(socket.set_only_v6(false), |e| {
            format!("set_only_v6 {:?}", e)
        })?;
    }
    io_convert(socket.set_reuse_address(true), |e| {
        format!("set_reuse_address {:?}", e)
    })?;
    io_convert(socket.set_nonblocking(true), |e| {
        format!("set_nonblocking {:?}", e)
    })?;
    io_convert(socket.bind(&address.into()), |e| {
        format!("bind {:?},{:?}", address, e)
    })?;
    Ok(socket.into())
}

#[inline]
pub fn io_convert<T, R: Display, F: FnOnce(&io::Error) -> R>(
    rs: io::Result<T>,
    f: F,
) -> io::Result<T> {
    rs.map_err(|e| io::Error::new(e.kind(), format!("{},internal error:{:?}", f(&e), e)))
}
