.PHONY: all build run test fuzz clean help

# Configuration parameters
FUZZ_TIME ?= 15
CARGO_CMD = cargo

# Default target
all: build

# 1. Build the project
build:
	@echo "==> Building BlackBox Project (Release)..."
	$(CARGO_CMD) build --release

# 2. Run the CLI
run:
	@echo "==> Running BlackBox CLI help..."
	$(CARGO_CMD) run --release -- --help

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
	@echo "  make build      - Compiles the project via cargo release"
	@echo "  make run        - Executes the compiled blackbox binary"
	@echo "  make test       - Executes ALL tests (Cargo Unittests, E2E, and Fuzzers sequentially)"
	@echo "  make test-core  - Executes only standard cargo tests (no fuzzing)"
	@echo "  make fuzz       - Executes only the libFuzzer chaos engines"
	@echo "  make clean      - Removes cargo target/, test profiles, fuzz artifacts, and object files"
