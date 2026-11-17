.PHONY: test pbt check clippy fmt clean

# 全テストを実行する
test:
	cargo test --workspace

# PBT を実行する
pbt:
	cargo test -p pbt

# cargo check を実行する
check:
	cargo check --workspace

# cargo clippy を実行する
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# cargo fmt を実行する
fmt:
	cargo fmt --all

# ビルド成果物を削除する
clean:
	cargo clean
