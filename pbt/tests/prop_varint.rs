//! 可変長整数のラウンドトリップと、非最小エンコーディングの受理。

use std::cell::Cell;

use noprop::{Ratio, Runner, sample_u64_in, sample_with_boundaries};
use shiguredo_masque::varint::{self, MAX};

#[test]
fn varint_roundtrip_covers_length_boundaries() -> noprop::TestResult {
    // 1 / 2 / 4 / 8 バイトの境目を必ず含む。
    let boundaries = [0u64, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, MAX];
    let saw_short = Cell::new(false);
    let saw_long = Cell::new(false);
    let seed = noprop::seed_from_env_or_time("MASQUE_VARINT_SEED")?;
    let mut runner = Runner::new(seed);
    runner.run(128, |ctx| {
        let value = sample_with_boundaries(ctx, &boundaries, Ratio::one_nth(3), |ctx| {
            sample_u64_in(ctx, 0..=MAX)
        });
        let mut encoded = Vec::new();
        varint::encode(value, &mut encoded).expect("範囲内の値はエンコードできる");
        let (decoded, len) = varint::decode(&encoded).expect("エンコード結果はデコードできる");
        assert_eq!(decoded, value);
        assert_eq!(len, encoded.len());
        if value <= 63 {
            saw_short.set(true);
        }
        if value > 1_073_741_823 {
            saw_long.set(true);
        }
        Ok(())
    })?;
    assert!(saw_short.get(), "1 バイトの値を通していない\n{runner}");
    assert!(saw_long.get(), "8 バイトの値を通していない\n{runner}");
    Ok(())
}

#[test]
fn non_minimal_varint_decodes_to_the_same_value() -> noprop::TestResult {
    // RFC 9000 Section 16 は非最小エンコーディングを拒否しない。
    let seed = noprop::seed_from_env_or_time("MASQUE_VARINT_NONMIN_SEED")?;
    let mut runner = Runner::new(seed);
    runner.run(64, |ctx| {
        let value = sample_u64_in(ctx, 0..=63);
        let mut wide = vec![0x80, 0, 0, 0];
        wide[3] = u8::try_from(value).expect("63 以下は 1 バイト");
        let (decoded, len) = varint::decode(&wide).expect("4 バイト形式を読める");
        assert_eq!(decoded, value);
        assert_eq!(len, 4);
        Ok(())
    })?;
    Ok(())
}
