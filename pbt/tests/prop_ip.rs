//! プレフィックス包含と経路のラウンドトリップ。

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::cell::Cell;

use noprop::{
    Ratio, Runner, sample_bool, sample_u32, sample_u64, sample_usize_in, sample_with_boundaries,
};
use shiguredo_masque::capsule::Capsule;
use shiguredo_masque::capsule::CapsuleDecoder;
use shiguredo_masque::ip::{IpPrefix, RouteRange};

fn masked_v4(addr: u32, prefix_len: u8) -> IpPrefix {
    let host = 32 - prefix_len;
    let masked = if host == 0 {
        addr
    } else if host >= 32 {
        0
    } else {
        addr & (!0u32 << host)
    };
    IpPrefix::new(Ipv4Addr::from(masked).into(), prefix_len).expect("マスク済み IPv4 は有効")
}

fn masked_v6(high: u64, low: u64, prefix_len: u8) -> IpPrefix {
    let bits = (u128::from(high) << 64) | u128::from(low);
    let host = 128 - prefix_len;
    let masked = if host == 0 {
        bits
    } else if host == 128 {
        0
    } else {
        bits & (!0u128 << host)
    };
    IpPrefix::new(Ipv6Addr::from(masked).into(), prefix_len).expect("マスク済み IPv6 は有効")
}

#[test]
fn prefix_contains_its_own_address_and_rejects_a_flipped_host_bit() -> noprop::TestResult {
    let saw_short = Cell::new(false);
    let saw_v6 = Cell::new(false);
    let seed = noprop::seed_from_env_or_time("MASQUE_PREFIX_SEED")?;
    let mut runner = Runner::new(seed);
    runner.run(128, |ctx| {
        let v4 = sample_bool(ctx);
        if v4 {
            let len = u8::try_from(sample_with_boundaries(
                ctx,
                &[0usize, 1, 31, 32],
                Ratio::one_nth(4),
                |ctx| sample_usize_in(ctx, 0..=32),
            ))
            .expect("32 以下は u8");
            let prefix = masked_v4(sample_u32(ctx), len);
            let IpAddr::V4(addr) = prefix.address else {
                panic!("IPv4 プレフィックスのアドレスは IPv4");
            };
            assert!(prefix.contains(prefix.address));
            if len == 0 {
                // /0 はどの IPv4 アドレスも含む。
                saw_short.set(true);
                assert!(prefix.contains(IpAddr::V4(Ipv4Addr::from(!u32::from(addr)))));
            } else if len == 32 {
                let flipped = IpAddr::V4(Ipv4Addr::from(u32::from(addr) ^ 1));
                assert!(!prefix.contains(flipped));
            } else {
                // ホストビットを反転しても中に入り、プレフィックスビットを反転すると外れる。
                saw_short.set(true);
                let inside = IpAddr::V4(Ipv4Addr::from(u32::from(addr) ^ 1));
                let outside = IpAddr::V4(Ipv4Addr::from(u32::from(addr) ^ (1u32 << (32 - len))));
                assert!(prefix.contains(inside));
                assert!(!prefix.contains(outside));
            }
        } else {
            saw_v6.set(true);
            let len = u8::try_from(sample_with_boundaries(
                ctx,
                &[0usize, 1, 64, 128],
                Ratio::one_nth(4),
                |ctx| sample_usize_in(ctx, 0..=128),
            ))
            .expect("128 以下は u8");
            let prefix = masked_v6(sample_u64(ctx), sample_u64(ctx), len);
            assert!(prefix.contains(prefix.address));
        }
        Ok(())
    })?;
    assert!(
        saw_short.get(),
        "短い IPv4 プレフィックスを通していない\n{runner}"
    );
    assert!(saw_v6.get(), "IPv6 プレフィックスを通していない\n{runner}");
    Ok(())
}

#[test]
fn route_advertisement_roundtrips() -> noprop::TestResult {
    let seed = noprop::seed_from_env_or_time("MASQUE_ROUTE_SEED")?;
    let mut runner = Runner::new(seed);
    runner.run(64, |ctx| {
        let start = sample_u32(ctx);
        let width = u32::try_from(sample_usize_in(ctx, 0..=1023)).expect("1023 は u32 に収まる");
        let end = start.saturating_add(width);
        let route = RouteRange::new(Ipv4Addr::from(start).into(), Ipv4Addr::from(end).into(), 17)
            .expect("始点に非負の幅を足した終点は始点以上");
        let capsule = Capsule::RouteAdvertisement(vec![route]);
        let bytes = capsule.encode().expect("単一範囲はエンコードできる");
        let mut decoder = CapsuleDecoder::new();
        decoder.push(&bytes).expect("追加できる");
        assert_eq!(decoder.poll().expect("読める"), Some(capsule));
        Ok(())
    })?;
    Ok(())
}
