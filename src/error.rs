//! プロトコルエラー
//!
//! ストリームを止める誤りと、IP パケット 1 個を捨てる誤りは別の型にする。
//! 後者は [`crate::connect_ip::SendError`] である。

use core::fmt;

/// カプセル列またはセッションを継続できない誤り
///
/// `Display` は英語である。呼び出し側のログにそのまま出せるようにするため。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// 可変長整数が 2^62-1 を超えている
    VarintOutOfRange,
    /// FIN の時点でカプセルが途中で切れている (RFC 9297 Section 3.3)
    Truncated,
    /// カプセル値や IP ヘッダの形が仕様と合わない
    Malformed,
    /// 制御カプセルの値がデコーダの上限を超えている
    CapsuleTooLarge,
    /// IP Version が 4 でも 6 でもない
    InvalidIpVersion,
    /// プレフィックス長がアドレス長を超えている
    InvalidPrefixLength,
    /// プレフィックス長に覆われない下位ビットが 0 ではない
    PrefixHostBits,
    /// 始点と終点のアドレスファミリが違う
    AddressFamilyMismatch,
    /// ADDRESS_REQUEST に Requested Address が無い (RFC 9484 Section 4.7.2)
    EmptyAddressRequest,
    /// ADDRESS_REQUEST の Request ID が 0 (RFC 9484 Section 4.7.2)
    RequestIdZero,
    /// Request ID を再利用した (RFC 9484 Section 4.7.2)
    RequestIdReuse,
    /// ROUTE_ADVERTISEMENT の並びが仕様の順序に反する (RFC 9484 Section 4.7.3)
    RouteUnordered,
    /// IP Protocol 0 の経路が他の経路とアドレス範囲で重なる (RFC 9484 Section 4.7.3)
    RouteOverlap,
    /// 始点アドレスが終点アドレスより大きい
    RouteInverted,
    /// PREF64 のプレフィックス長が 32 / 40 / 48 / 56 / 64 / 96 ではない
    InvalidNat64PrefixLength,
    /// PREF64 の 96 bit フィールドで、プレフィックス長より下のビットが 0 ではない
    Nat64PrefixBits,
    /// ドメイン名が FQDN の表示形式になっていない
    InvalidDomain,
    /// Nameserver の優先度が 0、またはアドレス数の制約に反する
    InvalidNameserver,
    /// Service Parameters のワイヤ形式が SVCB に反する
    InvalidServiceParameters,
    /// DNS Configuration の Nameserver Count が 0
    DnsNameserverCount,
    /// すでにストリームを破棄したセッションへの操作
    Aborted,
    /// Context ID 0 の UDP ペイロードが 65527 バイトを超えている (RFC 9298 Section 5)
    UdpPayloadTooLong,
    /// 記憶している Request ID が上限を超えた
    TooManyRequestIds,
    /// Context ID 0 を登録や close に使った
    ContextIdZero,
    /// 同じ Context ID か宛先を二度登録した
    DuplicateContext,
    /// クライアントは偶数、プロキシは奇数の Context ID しか割り当てられない
    BadContextParity,
    /// クライアント以外が圧縮しない Context ID を開いた
    UncompressedForbidden,
    /// 閉じたあとに使えない Context ID
    ClosedContext,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::VarintOutOfRange => "variable-length integer exceeds 2^62-1",
            Self::Truncated => "capsule stream ended before the last capsule was complete",
            Self::Malformed => "capsule or address field is malformed",
            Self::CapsuleTooLarge => "control capsule value exceeds the configured limit",
            Self::InvalidIpVersion => "IP version is neither 4 nor 6",
            Self::InvalidPrefixLength => "IP prefix length exceeds the address length",
            Self::PrefixHostBits => "host bits below the prefix length are not zero",
            Self::AddressFamilyMismatch => "start and end addresses use different IP versions",
            Self::EmptyAddressRequest => "ADDRESS_REQUEST contains no requested addresses",
            Self::RequestIdZero => "ADDRESS_REQUEST uses request ID 0",
            Self::RequestIdReuse => "request ID was reused",
            Self::RouteUnordered => "ROUTE_ADVERTISEMENT ranges are not ordered",
            Self::RouteOverlap => "ROUTE_ADVERTISEMENT ranges overlap",
            Self::RouteInverted => "route start address is greater than the end address",
            Self::InvalidNat64PrefixLength => {
                "NAT64 prefix length is not one of 32, 40, 48, 56, 64, 96"
            }
            Self::Nat64PrefixBits => "bits below the NAT64 prefix length are not zero",
            Self::InvalidDomain => "domain name is not an FQDN in display form",
            Self::InvalidNameserver => "nameserver priority or address list is invalid",
            Self::InvalidServiceParameters => "SVCB service parameters are invalid",
            Self::DnsNameserverCount => "DNS configuration contains zero nameservers",
            Self::Aborted => "MASQUE session is aborted",
            Self::UdpPayloadTooLong => "UDP payload exceeds 65527 bytes",
            Self::TooManyRequestIds => "too many address request IDs",
            Self::ContextIdZero => "context ID 0 is reserved",
            Self::DuplicateContext => "context ID or target is already registered",
            Self::BadContextParity => "context ID parity does not match the endpoint role",
            Self::UncompressedForbidden => "only the client may register an uncompressed context",
            Self::ClosedContext => "context ID is closed",
        };
        f.write_str(message)
    }
}

impl core::error::Error for Error {}
