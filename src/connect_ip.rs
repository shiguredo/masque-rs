//! CONNECT-IP の 1 ストリーム (RFC 9484)
//!
//! HTTP のリクエストとレスポンスが成功したあとのデータストリームを扱う。
//! ヘッダ、QUIC、TUN、NAT は持たない。
//!
//! 送信する IP パケットの宛先は、ピアが広告した経路か、自分がピアに代入した
//! プレフィックスのどちらかに入っていなければならない。後者は、リモートアクセス
//! VPN でプロキシがクライアントの代入アドレスへパケットを返すためである
//! (Section 8.1)。

use crate::capsule::{Capsule, CapsuleDecoder, Outbox};
use crate::datagram::HttpDatagram;
use crate::dns::{DnsConfiguration, Nat64Prefix};
use crate::error::Error;
use crate::ip::{
    self, AssignedAddress, IcmpError, IpPrefix, ParsedIp, RequestedAddress, RouteRange,
    is_assignment_rejection, is_link_local,
};
use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

/// 記憶する Request ID の上限
///
/// ピアが新しい ID を送り続けると状態が際限なく増える。上限を超えたらストリームを止める。
const MAX_REQUEST_IDS: usize = 1024;

/// リクエストの target。ホスト名の解決は呼び出し側が行う (RFC 9484 Section 4.6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetScope {
    /// `*` または省略。経路広告の範囲で送る
    Any,
    /// IP プレフィックス。この外へのパケットは送らない
    Prefix(IpPrefix),
    /// ホスト名。宛先の制限は、解決結果の経路広告に任せる
    Hostname(String),
}

/// CONNECT の target と ipproto
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestScope {
    /// 宛先の範囲
    pub target: TargetScope,
    /// 特定の IP プロトコル。`None` は任意。ICMP は常に許す
    pub ipproto: Option<u8>,
}

impl Default for RequestScope {
    fn default() -> Self {
        Self {
            target: TargetScope::Any,
            ipproto: None,
        }
    }
}

/// HTTP における役割
///
/// クライアントが CONNECT を送る側、プロキシが応答する側 (RFC 9484 Section 2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// CONNECT を送る側
    Client,
    /// IP プロキシ
    Proxy,
}

/// CONNECT-IP セッション
#[derive(Debug)]
pub struct ConnectIp {
    role: Role,
    decoder: CapsuleDecoder,
    outbox: Outbox,
    events: Vec<Event>,
    aborted: bool,
    /// ピアから代入された、自分の送信元プレフィックス
    assigned_to_us: Option<Vec<IpPrefix>>,
    /// 自分がピアへ代入したプレフィックス
    assigned_to_peer: Option<Vec<IpPrefix>>,
    /// ピアが広告した経路
    routes_from_peer: Vec<RouteRange>,
    /// 自分が広告した経路
    routes_we_advertised: Vec<RouteRange>,
    dns_from_peer: Vec<DnsConfiguration>,
    nat64_from_peer: Vec<Nat64Prefix>,
    local_request_ids: Vec<u64>,
    peer_request_ids: Vec<u64>,
    /// カプセル化した IP パケットの最大長。未設定なら検査しない
    max_ip_packet_len: Option<usize>,
    /// URI テンプレートの target と ipproto。未設定は任意
    scope: RequestScope,
}

/// ストリームから取り出すイベント
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// ピアからの ADDRESS_ASSIGN。使える送信元は [`ConnectIp::assigned_to_us`]
    AddressAssign(Vec<AssignedAddress>),
    /// ピアからの ADDRESS_REQUEST。応答の ADDRESS_ASSIGN は呼び出し側が作る
    AddressRequest(Vec<RequestedAddress>),
    /// ピアからの経路。以前の広告を置き換えた結果
    RouteAdvertisement(Vec<RouteRange>),
    /// ピアからの DNS 設定
    DnsAssign(Vec<DnsConfiguration>),
    /// ピアからの NAT64 プレフィックス
    Pref64(Vec<Nat64Prefix>),
    /// Context ID 0 の IP パケット。転送判定を通過している
    IpPacket(Vec<u8>),
    /// 登録されていない Context ID。データグラムは捨てる (RFC 9484 Section 6)
    UnknownContext {
        /// 未知の Context ID
        context_id: u64,
    },
    /// 転送判定で落とした受信パケット
    InboundRejected {
        /// 落とした理由
        reason: InboundReject,
        /// ピアへ返す ICMP IP パケット。作れないときは空
        icmp: Vec<u8>,
    },
}

/// 受信パケットを転送しない理由
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundReject {
    /// 送信元が、ピアに代入したプレフィックスの外 (RFC 9484 Section 11)
    BadSource,
    /// 宛先が、自分が広告した経路にも自分の代入アドレスにも入らない
    NoRoute,
    /// リンクローカルをトンネルの外へ出さない (RFC 9484 Section 7.2)
    LinkLocal,
    /// IP ヘッダとして読めない
    Malformed,
}

/// IP パケットを HTTP Datagram に載せる前の拒否
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// セッションはすでに破棄されている
    Aborted,
    /// IP ヘッダとして読めない
    MalformedIp,
    /// リンクローカル
    LinkLocal,
    /// 送信元が自分に代入されたプレフィックスの外
    BadSource,
    /// 宛先に合う経路が無い
    NoRoute,
    /// 設定した最大長を超えている。`icmp` は Packet Too Big
    PacketTooBig {
        /// 入る最大の IP パケット長
        mtu: u32,
        /// 送信元へ返す ICMP IP パケット
        icmp: Vec<u8>,
    },
    /// TTL / Hop Limit を減らせない。`icmp` は Time Exceeded
    HopLimitExceeded {
        /// 送信元へ返す ICMP IP パケット
        icmp: Vec<u8>,
    },
    /// スコープ外、または ICMP 以外で ipproto と一致しない
    OutOfScope,
    /// IPv6 を運ぶには HTTP Datagram で 1280 バイト必要 (RFC 9484 Section 7.2)
    Ipv6LinkMtu,
}

impl ConnectIp {
    /// セッションを作る
    ///
    /// `role` は HTTP のクライアントかプロキシか。アドレスプールは持たない。
    pub fn new(role: Role) -> Self {
        Self {
            role,
            decoder: CapsuleDecoder::new(),
            outbox: Outbox::default(),
            events: Vec::new(),
            aborted: false,
            assigned_to_us: None,
            assigned_to_peer: None,
            routes_from_peer: Vec::new(),
            routes_we_advertised: Vec::new(),
            dns_from_peer: Vec::new(),
            nat64_from_peer: Vec::new(),
            local_request_ids: Vec::new(),
            peer_request_ids: Vec::new(),
            max_ip_packet_len: None,
            scope: RequestScope::default(),
        }
    }

    /// HTTP 上の役割
    pub fn role(&self) -> Role {
        self.role
    }

    /// ストリームを破棄済みか
    pub fn is_aborted(&self) -> bool {
        self.aborted
    }

    /// ピアに代入された送信元プレフィックス
    ///
    /// まだ ADDRESS_ASSIGN を受け取っていなければ `None`。
    /// 空の代入を受け取ったあとは空スライスで、どの送信元も使えない。
    pub fn assigned_to_us(&self) -> Option<&[IpPrefix]> {
        self.assigned_to_us.as_deref()
    }

    /// ピアが広告した経路
    pub fn routes_from_peer(&self) -> &[RouteRange] {
        &self.routes_from_peer
    }

    /// ピアが送った DNS 設定
    pub fn dns_from_peer(&self) -> &[DnsConfiguration] {
        &self.dns_from_peer
    }

    /// ピアが送った NAT64 プレフィックス
    pub fn nat64_from_peer(&self) -> &[Nat64Prefix] {
        &self.nat64_from_peer
    }

    /// カプセル化できる IP パケットの最大長を設定する
    ///
    /// QUIC の DATAGRAM に入る長さは呼び出し側が知っている (RFC 9484 Section 10.1)。
    /// 超えたパケットは DATAGRAM カプセルへ逃がさず、Packet Too Big を返す。
    /// IPv6 を運ぶときは 1280 バイト未満だとストリームを止める (Section 7.2)。
    pub fn set_max_ip_packet_len(&mut self, max: usize) {
        self.max_ip_packet_len = Some(max);
    }

    /// リクエストの target と ipproto を設定する (RFC 9484 Section 4.6)
    pub fn set_scope(&mut self, scope: RequestScope) {
        self.scope = scope;
    }

    /// データストリームのバイトを入れる
    ///
    /// 揃ったカプセルは [`Self::poll_event`] に並ぶ。
    /// `fin` が真でカプセルが途中なら [`Error::Truncated`] でセッションを破棄する。
    pub fn recv_stream(&mut self, data: &[u8], fin: bool) -> Result<(), Error> {
        self.ensure()?;
        if let Err(err) = self.decoder.push(data) {
            self.aborted = true;
            return Err(err);
        }
        loop {
            match self.decoder.poll() {
                Ok(Some(capsule)) => self.apply(capsule)?,
                Ok(None) => break,
                Err(err) => {
                    self.aborted = true;
                    return Err(err);
                }
            }
        }
        if fin && let Err(err) = self.decoder.finish() {
            self.aborted = true;
            return Err(err);
        }
        Ok(())
    }

    /// QUIC DATAGRAM から Quarter Stream ID を除いたペイロードを入れる
    ///
    /// 形が壊れていてもセッションは破棄しない。信頼性の無いデータグラムだからである。
    /// カプセル上の DATAGRAM は [`Self::recv_stream`] が扱い、壊れていれば破棄する。
    pub fn recv_http_datagram(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.ensure()?;
        let datagram = HttpDatagram::decode(payload)?;
        self.take_datagram(datagram);
        Ok(())
    }

    /// 次の受信イベント
    pub fn poll_event(&mut self) -> Option<Event> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }

    /// 次にデータストリームへ書くカプセル
    pub fn poll_capsule(&mut self) -> Option<Vec<u8>> {
        self.outbox.pop()
    }

    /// ADDRESS_REQUEST を送る
    pub fn queue_address_request(&mut self, list: Vec<RequestedAddress>) -> Result<(), Error> {
        self.ensure()?;
        let ids = request_ids(&list);
        check_request_ids(&self.local_request_ids, &ids)?;
        let bytes = Capsule::AddressRequest(list).encode()?;
        self.local_request_ids.extend(ids);
        self.outbox.push(bytes);
        Ok(())
    }

    /// ADDRESS_ASSIGN を送る
    ///
    /// 全 0 かつ最大長の要素は拒否であり、ピアの送信元には数えない
    /// (RFC 9484 Section 4.7.2)。
    pub fn queue_address_assign(&mut self, list: Vec<AssignedAddress>) -> Result<(), Error> {
        self.ensure()?;
        let bytes = Capsule::AddressAssign(list.clone()).encode()?;
        self.assigned_to_peer = Some(usable_prefixes(&list));
        self.outbox.push(bytes);
        Ok(())
    }

    /// ROUTE_ADVERTISEMENT を送る
    ///
    /// このカプセルは、同じ方向の以前の広告をすべて置き換える (RFC 9484 Section 4.7.3)。
    pub fn queue_route_advertisement(&mut self, list: Vec<RouteRange>) -> Result<(), Error> {
        self.ensure()?;
        let bytes = Capsule::RouteAdvertisement(list.clone()).encode()?;
        self.routes_we_advertised = list;
        self.outbox.push(bytes);
        Ok(())
    }

    /// DNS_ASSIGN を送る
    pub fn queue_dns_assign(&mut self, list: Vec<DnsConfiguration>) -> Result<(), Error> {
        self.ensure()?;
        let bytes = Capsule::DnsAssign(list).encode()?;
        self.outbox.push(bytes);
        Ok(())
    }

    /// PREF64 を送る
    pub fn queue_pref64(&mut self, list: Vec<Nat64Prefix>) -> Result<(), Error> {
        self.ensure()?;
        let bytes = Capsule::Pref64(list).encode()?;
        self.outbox.push(bytes);
        Ok(())
    }

    /// IP パケットを HTTP Datagram ペイロードにする
    ///
    /// 戻り値は Context ID 0 とパケットであり、Quarter Stream ID は含まない。
    /// `generated_by_endpoint` が偽のときは、載せる直前に Hop Limit を 1 減らす
    /// (RFC 9484 Section 7.2)。エンドポイント自身が作った ICMP では真にする。
    pub fn send_ip_packet(
        &mut self,
        packet: &[u8],
        generated_by_endpoint: bool,
    ) -> Result<Vec<u8>, SendError> {
        if self.aborted {
            return Err(SendError::Aborted);
        }
        let parsed = ip::parse_ip(packet).map_err(|_| SendError::MalformedIp)?;
        if is_link_local(parsed.src) || is_link_local(parsed.dst) {
            return Err(SendError::LinkLocal);
        }
        if !scope_allows(&self.scope, &parsed) {
            return Err(SendError::OutOfScope);
        }
        if matches!(parsed.src, IpAddr::V6(_))
            && self.max_ip_packet_len.is_some_and(|max| max < 1280)
        {
            self.aborted = true;
            return Err(SendError::Ipv6LinkMtu);
        }
        if let Some(prefixes) = &self.assigned_to_us
            && !prefixes.iter().any(|prefix| prefix.contains(parsed.src))
        {
            return Err(SendError::BadSource);
        }
        if !self.outbound_destination_allowed(&parsed) {
            return Err(SendError::NoRoute);
        }
        let forwarded = if generated_by_endpoint {
            packet.to_vec()
        } else {
            match ip::decrement_hop_limit(packet).map_err(|_| SendError::MalformedIp)? {
                Some(packet) => packet,
                None => {
                    let icmp = icmp_or_empty(packet, IcmpError::HopLimitExceeded, 0);
                    return Err(SendError::HopLimitExceeded { icmp });
                }
            }
        };
        if let Some(max) = self.max_ip_packet_len
            && forwarded.len() > max
        {
            let mtu = u32::try_from(max).unwrap_or(u32::MAX);
            let icmp = icmp_or_empty(packet, IcmpError::PacketTooBig, mtu);
            return Err(SendError::PacketTooBig { mtu, icmp });
        }
        let mut out = Vec::new();
        HttpDatagram {
            context_id: 0,
            payload: forwarded,
        }
        .encode(&mut out)
        .expect("Context ID 0 は可変長整数に収まる (実装バグならパニック)");
        Ok(out)
    }

    fn apply(&mut self, capsule: Capsule) -> Result<(), Error> {
        match capsule {
            Capsule::Datagram(datagram) => {
                self.take_datagram(datagram);
                Ok(())
            }
            Capsule::AddressAssign(list) => {
                self.assigned_to_us = Some(usable_prefixes(&list));
                self.events.push(Event::AddressAssign(list));
                Ok(())
            }
            Capsule::AddressRequest(list) => {
                let ids = request_ids(&list);
                check_request_ids(&self.peer_request_ids, &ids)?;
                self.peer_request_ids.extend(ids);
                self.events.push(Event::AddressRequest(list));
                Ok(())
            }
            Capsule::RouteAdvertisement(list) => {
                self.routes_from_peer = list.clone();
                self.events.push(Event::RouteAdvertisement(list));
                Ok(())
            }
            Capsule::DnsAssign(list) => {
                self.dns_from_peer = list.clone();
                self.events.push(Event::DnsAssign(list));
                Ok(())
            }
            Capsule::Pref64(list) => {
                self.nat64_from_peer = list.clone();
                self.events.push(Event::Pref64(list));
                Ok(())
            }
            // CONNECT-IP が定義しないカプセルは、未知タイプと同じく捨てる (RFC 9297 Section 3.2)。
            _ => Ok(()),
        }
    }

    fn take_datagram(&mut self, datagram: HttpDatagram) {
        if datagram.context_id != 0 {
            self.events.push(Event::UnknownContext {
                context_id: datagram.context_id,
            });
            return;
        }
        match classify_inbound(self, &datagram.payload) {
            InboundClass::Accept => self.events.push(Event::IpPacket(datagram.payload)),
            InboundClass::Reject { reason, icmp } => {
                self.events.push(Event::InboundRejected { reason, icmp });
            }
        }
    }

    fn outbound_destination_allowed(&self, parsed: &ParsedIp) -> bool {
        self.routes_from_peer
            .iter()
            .any(|route| route_matches(*route, parsed))
            || self
                .assigned_to_peer
                .as_ref()
                .is_some_and(|prefixes| prefixes.iter().any(|prefix| prefix.contains(parsed.dst)))
    }

    fn ensure(&self) -> Result<(), Error> {
        if self.aborted {
            Err(Error::Aborted)
        } else {
            Ok(())
        }
    }
}

enum InboundClass {
    Accept,
    Reject {
        reason: InboundReject,
        icmp: Vec<u8>,
    },
}

fn classify_inbound(session: &ConnectIp, packet: &[u8]) -> InboundClass {
    let parsed = match ip::parse_ip(packet) {
        Ok(parsed) => parsed,
        Err(_) => {
            return InboundClass::Reject {
                reason: InboundReject::Malformed,
                icmp: Vec::new(),
            };
        }
    };
    if is_link_local(parsed.src) || is_link_local(parsed.dst) {
        return InboundClass::Reject {
            reason: InboundReject::LinkLocal,
            icmp: Vec::new(),
        };
    }
    if let Some(prefixes) = &session.assigned_to_peer
        && !prefixes.iter().any(|prefix| prefix.contains(parsed.src))
    {
        return InboundClass::Reject {
            reason: InboundReject::BadSource,
            icmp: icmp_or_empty(packet, IcmpError::BadSource, 0),
        };
    }
    if !inbound_destination_allowed(session, parsed.dst) {
        return InboundClass::Reject {
            reason: InboundReject::NoRoute,
            icmp: icmp_or_empty(packet, IcmpError::NoRoute, 0),
        };
    }
    InboundClass::Accept
}

fn inbound_destination_allowed(session: &ConnectIp, dst: IpAddr) -> bool {
    if session
        .routes_we_advertised
        .iter()
        .any(|route| route.contains(dst))
    {
        return true;
    }
    if session
        .assigned_to_us
        .as_ref()
        .is_some_and(|prefixes| prefixes.iter().any(|prefix| prefix.contains(dst)))
    {
        return true;
    }
    // まだ経路もアドレスも無い。設定前のパケットは呼び出し側に渡す。
    session.routes_we_advertised.is_empty() && session.assigned_to_us.is_none()
}

fn scope_allows(scope: &RequestScope, parsed: &ParsedIp) -> bool {
    if let TargetScope::Prefix(prefix) = &scope.target
        && !prefix.contains(parsed.dst)
    {
        return false;
    }
    if let Some(protocol) = scope.ipproto
        && parsed.protocol != protocol
        && !icmp_protocol(parsed)
    {
        return false;
    }
    true
}

fn route_matches(route: RouteRange, parsed: &ParsedIp) -> bool {
    if !route.contains(parsed.dst) {
        return false;
    }
    // ICMP は IP Protocol 欄の値に関わらず通す (RFC 9484 Section 4.7.3)。
    route.protocol == 0 || route.protocol == parsed.protocol || icmp_protocol(parsed)
}

fn icmp_protocol(parsed: &ParsedIp) -> bool {
    match parsed.src {
        IpAddr::V4(_) => parsed.protocol == ip::IPV4_ICMP,
        IpAddr::V6(_) => parsed.protocol == ip::IPV6_ICMP,
    }
}

fn usable_prefixes(list: &[AssignedAddress]) -> Vec<IpPrefix> {
    list.iter()
        .filter(|item| !is_assignment_rejection(item.prefix))
        .map(|item| item.prefix)
        .collect()
}

fn request_ids(list: &[RequestedAddress]) -> Vec<u64> {
    list.iter().map(|item| item.request_id).collect()
}

fn check_request_ids(existing: &[u64], incoming: &[u64]) -> Result<(), Error> {
    let mut seen = Vec::new();
    for id in incoming {
        if existing.contains(id) || seen.contains(id) {
            return Err(Error::RequestIdReuse);
        }
        seen.push(*id);
    }
    if existing.len() + seen.len() > MAX_REQUEST_IDS {
        return Err(Error::TooManyRequestIds);
    }
    Ok(())
}

fn icmp_or_empty(packet: &[u8], kind: IcmpError, mtu: u32) -> Vec<u8> {
    ip::icmp_error(packet, kind, mtu).unwrap_or_default()
}
