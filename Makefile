.PHONY: all build run test fuzz clean help

# Configuration — override via environment or .env file
-include .env
FUZZ_TIME ?= 15
CARGO_CMD = cargo
TEAM_ID ?= $(error Set TEAM_ID in .env or environment, e.g. TEAM_ID=XXXXXXXXXX)
SIGN_IDENTITY ?= Apple Development
PROVISION_PROFILE ?= $(error Set PROVISION_PROFILE in .env, e.g. PROVISION_PROFILE=path/to/file.provisionprofile)
APP_BUNDLE = target/release/BlackBox.app

# Default target
all: build

# 1. Build the project and create signed .app bundle
build:
	@echo "==> Building BlackBox Project (Release)..."
	$(CARGO_CMD) build --release
	@echo "==> Creating BlackBox.app Bundle..."
	@mkdir -p $(APP_BUNDLE)/Contents/MacOS
	@cp target/release/blackbox $(APP_BUNDLE)/Contents/MacOS/blackbox
	@cp tools/macos_signing/Info.plist $(APP_BUNDLE)/Contents/Info.plist
	@cp "$(PROVISION_PROFILE)" $(APP_BUNDLE)/Contents/embedded.provisionprofile
	@echo "==> Signing BlackBox.app with Secure Enclave Entitlements..."
	codesign -s "$(SIGN_IDENTITY)" --entitlements tools/macos_signing/entitlements.plist --force $(APP_BUNDLE)
	@echo "==> Creating convenience symlink..."
	@ln -sf BlackBox.app/Contents/MacOS/blackbox target/release/bb
	@echo "==> Build complete! Run with: ./target/release/bb"

# 2. Run the CLI
run:
	@echo "==> Running BlackBox CLI help..."
	$(APP_BUNDLE)/Contents/MacOS/blackbox --help

# 3. Test execution (Unit, Integration, and Concurrency)
test-core:
	@echo "==> Running Standard Cargo Tests (Unit & E2E)..."
	$(CARGO_CMD) test --all

# 4. Continuous Fuzzing execution
fuzz:
	@echo "==> Running Fuzzers via Nightly Compiler (Max Time: $(FUZZ_TIME)s per target)..."
	@echo "--> Fuzzing ANSI Sanitizer..."
	cargo +nightly fuzz run fuzz_ansi -- -max_total_time=$(FUZZ_TIME)
	@echo "--> Fuzzing Hex Parser..."
	cargo +nightly fuzz run fuzz_parser -- -max_total_time=$(FUZZ_TIME)
	@echo "--> Fuzzing Crypto Engine..."
	cargo +nightly fuzz run fuzz_crypto_decrypt -- -max_total_time=$(FUZZ_TIME)
	@echo "--> Fuzzing Layout Parsers..."
	cargo +nightly fuzz run fuzz_layout_parse -- -max_total_time=$(FUZZ_TIME)
	@echo "--> Fuzzing Space Manager..."
	cargo +nightly fuzz run fuzz_space_manager -- -max_total_time=$(FUZZ_TIME)

# 5. Combined Testing sequence
test: test-core fuzz
	@echo "==> All Tests (Core + Fuzzing) completed successfully!"

# 6. Cleaning all artifacts
clean:
	@echo "==> Cleaning Build and Fuzzing Artifacts..."
	$(CARGO_CMD) clean
	rm -rf fuzz/artifacts/
	rm -rf fuzz/corpus/
	find . -type f -name "*.profraw" -delete
	find . -type f -name "*.profdata" -delete
	rm -rf coverage/
	@echo "==> Project cleaned!"

# 7. Help directive
help:
	@echo "BlackBox Makefile Commands:"
	@echo "  make all        - Builds the release binaries"
	@echo "  make build      - Compiles, bundles, and signs BlackBox.app for Secure Enclave"
	@echo "  make run        - Executes the compiled blackbox binary"
	@echo "  make test       - Executes ALL tests (Cargo Unittests, E2E, and Fuzzers sequentially)"
	@echo "  make test-core  - Executes only standard cargo tests (no fuzzing)"
	@echo "  make fuzz       - Executes only the libFuzzer chaos engines"
	@echo "  make clean      - Removes cargo target/, test profiles, fuzz artifacts, and object files"
	@echo ""
	@echo "Setup: Copy .env.example to .env and fill in your Apple credentials"
