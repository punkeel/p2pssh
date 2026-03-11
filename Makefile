.PHONY: fmt lint build build-release

fmt:
	cargo fmt

lint:
	cargo clippy

build:
	cargo build

build-release:
	cargo build --release
