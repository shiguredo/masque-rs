#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_masque::capsule::CapsuleDecoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = CapsuleDecoder::new();
    if decoder.push(data).is_err() {
        return;
    }
    loop {
        match decoder.poll() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => return,
        }
    }
    let _ = decoder.finish();
});
