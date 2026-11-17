//! `masque --help` が proxy と client を出すことを確認する。

use std::process::Command;

#[test]
fn help_lists_proxy_and_client() {
    let output = Command::new(env!("CARGO_BIN_EXE_masque"))
        .arg("--help")
        .output()
        .expect("masque --help を実行できる");
    assert!(
        output.status.success(),
        "ヘルプは成功終了する: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("ヘルプは UTF-8");
    assert!(stdout.contains("proxy"), "proxy がヘルプにある: {stdout}");
    assert!(stdout.contains("client"), "client がヘルプにある: {stdout}");
}

#[test]
fn client_help_lists_tun() {
    let output = Command::new(env!("CARGO_BIN_EXE_masque"))
        .args(["client", "--help"])
        .output()
        .expect("masque client --help を実行できる");
    assert!(
        output.status.success(),
        "ヘルプは成功終了する: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("ヘルプは UTF-8");
    assert!(stdout.contains("--tun"), "tun がヘルプにある: {stdout}");
}
