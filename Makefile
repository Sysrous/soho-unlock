# Cross-compile for Linux (run from Windows with musl toolchain)
# Prerequisites: rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

BINARY = soho-unlock
VERSION = $(shell grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)

.PHONY: all linux-amd64 linux-arm64 windows clean

all: linux-amd64 linux-arm64

linux-amd64:
	cross build --release --target x86_64-unknown-linux-musl
	cp target/x86_64-unknown-linux-musl/release/$(BINARY) $(BINARY)-linux-amd64

linux-arm64:
	cross build --release --target aarch64-unknown-linux-musl
	cp target/aarch64-unknown-linux-musl/release/$(BINARY) $(BINARY)-linux-arm64

windows:
	cargo build --release
	cp target/release/$(BINARY).exe $(BINARY)-windows-amd64.exe

clean:
	cargo clean
	rm -f $(BINARY)-linux-* $(BINARY)-windows-*
