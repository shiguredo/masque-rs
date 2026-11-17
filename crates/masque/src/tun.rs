//! macOS の utun を開き、IP パケットを読み書きする。
//!
//! 代入アドレスは /32 で載せ、プロキシが配るネットワークへの経路は `route` で足す。
//! NAT はしない。utun 以外の OS では [`Tun::open`] が失敗する。

use std::net::Ipv4Addr;
use std::process::Command;

#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "macos")]
use tokio::io::unix::AsyncFd;

/// utun フレームの先頭にあるアドレスファミリの長さ
#[cfg(target_os = "macos")]
const FAMILY_LEN: usize = 4;

/// 読み取る utun フレームの上限。IPv4 の最大長にファミリを足した値
#[cfg(target_os = "macos")]
const FRAME_MAX: usize = 65535 + FAMILY_LEN;

#[cfg(target_os = "macos")]
const AF_INET: u32 = 2;
#[cfg(target_os = "macos")]
const AF_INET6: u32 = 30;

/// `fcntl.h` の `FD_CLOEXEC`
#[cfg(target_os = "macos")]
const FD_CLOEXEC: libc::c_int = 1;

/// `CTLIOCGINFO`。`_IOWR('N', 3, struct ctl_info)` で、`ctl_info` は 100 バイト
#[cfg(target_os = "macos")]
const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;

#[cfg(target_os = "macos")]
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
#[cfg(target_os = "macos")]
const UTUN_OPT_IFNAME: libc::c_int = 2;
#[cfg(target_os = "macos")]
const IFNAMSIZ: usize = 16;

/// `sys/kern_control.h` の `ctl_info`
#[cfg(target_os = "macos")]
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

/// `sys/kern_control.h` の `sockaddr_ctl`
#[cfg(target_os = "macos")]
#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::size_of::<CtlInfo>() == 100);
#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::size_of::<SockaddrCtl>() == 32);

/// OS の TUN
///
/// macOS では utun である。ドロップするとソケットが閉じ、インターフェースは消える。
/// 足した経路はドロップ時に削除する。
pub struct Tun {
    name: String,
    /// `route delete` に渡す宛先。経路を足していないときは空
    installed_route: Option<String>,
    #[cfg(target_os = "macos")]
    fd: AsyncFd<OwnedFd>,
    #[cfg(target_os = "macos")]
    frame: Vec<u8>,
}

impl Tun {
    /// 新しい TUN を開く
    ///
    /// Tokio のランタイム上で呼ぶ。アドレスはまだ載っていない。[`Self::assign_ipv4`] が載せる。
    pub fn open() -> Result<Self, String> {
        #[cfg(target_os = "macos")]
        {
            let (fd, name) = open_utun()?;
            tracing::info!(iface = %name, "opened tun");
            Ok(Self {
                name,
                installed_route: None,
                fd,
                frame: vec![0; FRAME_MAX],
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err("TUN is only implemented on macOS".to_string())
        }
    }

    /// インターフェース名
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `address` を /32 で載せ、`network`/`prefix_len` 宛の経路をこのインターフェースへ向ける
    ///
    /// `ifconfig` と `route` を使う。失敗したときは権限不足がほとんどである。
    /// 同じホストに TUN が 2 つあると、後から足した経路が先の経路を置き換える。
    pub fn assign_ipv4(
        &mut self,
        address: Ipv4Addr,
        network: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), String> {
        if prefix_len > 32 {
            return Err(format!("prefix length {prefix_len} is longer than 32"));
        }
        let address = address.to_string();
        run(
            "/sbin/ifconfig",
            &[
                self.name.as_str(),
                "inet",
                address.as_str(),
                address.as_str(),
                "netmask",
                "255.255.255.255",
                "up",
            ],
        )?;
        let destination = format!("{network}/{prefix_len}");
        // 前回の実験で残った同じ宛先を消してから足す。TEST-NET-1 以外は触らない。
        let _ = run(
            "/sbin/route",
            &[
                "-n",
                "delete",
                "-net",
                destination.as_str(),
                "-interface",
                self.name.as_str(),
            ],
        );
        run(
            "/sbin/route",
            &[
                "-n",
                "add",
                "-net",
                destination.as_str(),
                "-interface",
                self.name.as_str(),
            ],
        )?;
        self.installed_route = Some(destination);
        tracing::info!(iface = %self.name, %address, "assigned tun address");
        Ok(())
    }

    /// カーネルが書いた次の IP パケットを返す
    ///
    /// 戻り値に utun のファミリヘッダは含まれない。
    pub async fn read_packet(&mut self) -> Result<Vec<u8>, String> {
        #[cfg(target_os = "macos")]
        {
            let fd = &self.fd;
            let frame = &mut self.frame;
            loop {
                let mut guard = fd.readable().await.map_err(|err| err.to_string())?;
                let result = guard.try_io(|inner| read_once(inner.get_ref(), frame));
                match result {
                    Ok(Ok(len)) => return packet_from_frame(&frame[..len]),
                    Ok(Err(err)) => return Err(err.to_string()),
                    Err(_would_block) => continue,
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err("TUN is only implemented on macOS".to_string())
        }
    }

    /// IP パケットをカーネルへ書く
    ///
    /// macOS では先頭にアドレスファミリを付ける。
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            let header = utun_header(packet)?;
            let fd = &self.fd;
            loop {
                let mut guard = fd.writable().await.map_err(|err| err.to_string())?;
                let result = guard.try_io(|inner| write_once(inner.get_ref(), &header, packet));
                match result {
                    Ok(Ok(())) => return Ok(()),
                    Ok(Err(err)) => return Err(err.to_string()),
                    Err(_would_block) => continue,
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = packet;
            Err("TUN is only implemented on macOS".to_string())
        }
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        let Some(destination) = self.installed_route.take() else {
            return;
        };
        let output = Command::new("/sbin/route")
            .args([
                "-n",
                "delete",
                "-net",
                destination.as_str(),
                "-interface",
                self.name.as_str(),
            ])
            .output();
        match output {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::info!(iface = %self.name, %stderr, "failed to delete tun route");
            }
            Err(err) => tracing::info!(iface = %self.name, %err, "failed to delete tun route"),
        }
    }
}

#[cfg(target_os = "macos")]
fn open_utun() -> Result<(AsyncFd<OwnedFd>, String), String> {
    // socket の戻り値は、この OwnedFd に渡すまで所有者がいない。
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(os_err("utun socket"));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_cloexec(&fd)?;
    let mut info = CtlInfo {
        ctl_id: 0,
        ctl_name: [0; 96],
    };
    info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
    // info は有効な ctl_info で、fd は開いた制御ソケットである。
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) };
    if rc < 0 {
        return Err(os_err("utun ioctl"));
    }
    let addr = SockaddrCtl {
        sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        // sc_unit 0 は、カーネルに空いている utun 番号を選ばせる。
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&addr as *const SockaddrCtl).cast(),
            std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(os_err("utun connect"));
    }
    let name = interface_name(&fd)?;
    set_nonblocking(&fd)?;
    // OwnedFd はこの AsyncFd がドロップされるまで同じ fd のまま保持する。
    let async_fd = unsafe { AsyncFd::register(fd) }.map_err(|err| err.to_string())?;
    Ok((async_fd, name))
}

#[cfg(target_os = "macos")]
fn interface_name(fd: &OwnedFd) -> Result<String, String> {
    let mut name = [0u8; IFNAMSIZ];
    let mut len = name.len() as libc::socklen_t;
    // name は IFNAMSIZ バイトあり、len はその長さを示す。
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(os_err("utun name"));
    }
    let n = (len as usize).min(name.len());
    let end = name[..n].iter().position(|byte| *byte == 0).unwrap_or(n);
    String::from_utf8(name[..end].to_vec()).map_err(|err| err.to_string())
}

#[cfg(target_os = "macos")]
fn set_cloexec(fd: &OwnedFd) -> Result<(), String> {
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, FD_CLOEXEC) };
    if rc < 0 {
        return Err(os_err("utun cloexec"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_nonblocking(fd: &OwnedFd) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(os_err("utun fcntl"));
    }
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(os_err("utun fcntl"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn read_once(fd: &OwnedFd, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        // buf はこの呼び出しの間だけ有効で、長さは buf.len() を超えない。
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(target_os = "macos")]
fn write_once(fd: &OwnedFd, header: &[u8; FAMILY_LEN], packet: &[u8]) -> std::io::Result<()> {
    let iov = [
        libc::iovec {
            iov_base: header.as_ptr() as *mut libc::c_void,
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: packet.as_ptr() as *mut libc::c_void,
            iov_len: packet.len(),
        },
    ];
    loop {
        // 制御ソケットへの 1 回の writev が 1 個の utun データグラムになる。
        let n = unsafe { libc::writev(fd.as_raw_fd(), iov.as_ptr(), iov.len() as i32) };
        if n >= 0 {
            if n as usize != header.len() + packet.len() {
                return Err(std::io::Error::other("short utun write"));
            }
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(target_os = "macos")]
fn utun_header(packet: &[u8]) -> Result<[u8; FAMILY_LEN], String> {
    let family = match packet.first().copied().unwrap_or(0) >> 4 {
        4 => AF_INET,
        6 => AF_INET6,
        _ => return Err("tun packet is not IPv4 or IPv6".to_string()),
    };
    Ok(family.to_be_bytes())
}

#[cfg(target_os = "macos")]
fn packet_from_frame(frame: &[u8]) -> Result<Vec<u8>, String> {
    let header = frame
        .get(..FAMILY_LEN)
        .ok_or_else(|| "short utun frame".to_string())?;
    let family = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let packet = &frame[FAMILY_LEN..];
    let version = packet.first().copied().unwrap_or(0) >> 4;
    let matches = (family == AF_INET && version == 4) || (family == AF_INET6 && version == 6);
    if !matches {
        return Err(format!("unexpected utun family {family}"));
    }
    Ok(packet.to_vec())
}

#[cfg(target_os = "macos")]
fn os_err(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("{program}: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(format!(
        "{program} {} failed: {stderr}{stdout}",
        args.join(" ")
    ))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::packet_from_frame;

    #[test]
    fn strips_the_ipv4_family_header() {
        let frame = [0, 0, 0, 2, 0x45, 0, 0, 20];
        let packet = packet_from_frame(&frame).expect("IPv4 の utun フレームを外せる");
        assert_eq!(packet, [0x45, 0, 0, 20]);
    }

    #[test]
    fn strips_the_ipv6_family_header() {
        let frame = [0, 0, 0, 30, 0x60, 0, 0, 0];
        let packet = packet_from_frame(&frame).expect("IPv6 の utun フレームを外せる");
        assert_eq!(packet, [0x60, 0, 0, 0]);
    }

    #[test]
    fn rejects_a_short_frame() {
        let err = packet_from_frame(&[0, 0, 0]).expect_err("4 バイト未満はフレームではない");
        assert!(err.contains("short"), "短いフレームのエラー: {err}");
    }

    #[test]
    fn puts_the_ipv4_family_back() {
        let packet = [0x45, 0, 0, 20];
        let header = super::utun_header(&packet).expect("IPv4 のファミリを付けられる");
        let mut frame = header.to_vec();
        frame.extend_from_slice(&packet);
        let back = packet_from_frame(&frame).expect("付けたファミリを外せる");
        assert_eq!(back, packet);
    }

    #[test]
    fn rejects_a_mismatched_family() {
        let err = packet_from_frame(&[0, 0, 0, 2, 0x60]).expect_err("ファミリと版が違う");
        assert!(err.contains("family"), "不一致のエラー: {err}");
    }
}
