all: build cp

build:
		@echo "Building project in release mode..." \
		cargo build --release

cp:
		@echo "Copy bin to /usr/bin/sock5proxy"
		cp target/release/sock5proxy /usr/bin/

clean:
		@echo "Cleaning up..."
		cargo clean

.PHONY: all build cp clean
