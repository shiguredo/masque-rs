#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_masque::varint;

fuzz_target!(|data: &[u8]| {
    let _ = varint::decode(data);
});
