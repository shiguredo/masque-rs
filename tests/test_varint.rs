//! 可変長整数の範囲外。ラウンドトリップは pbt に置く。

use shiguredo_masque::error::Error;
use shiguredo_masque::varint;

#[test]
fn encode_rejects_values_above_the_quic_maximum() {
    let mut buf = Vec::new();
    assert_eq!(
        varint::encode(1 << 62, &mut buf),
        Err(Error::VarintOutOfRange)
    );
    assert!(buf.is_empty());
}

#[test]
fn decode_of_a_short_buffer_is_incomplete() {
    // 上位 2 bit が 4 バイト長を示しているのに、後続が無い。
    assert_eq!(varint::decode(&[0x80, 0x00]), None);
}
