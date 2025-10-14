# Makefile for the local network scanner tool
# Provides shortcuts for testing and installation hints.

APP_NAME = localnet

.PHONY: all test install clean

all:
	@echo "Available targets:"
	@echo "  make test     - run all unit tests"
	@echo "  make install  - show installation instructions"
	@echo "  make clean    - remove __pycache__ and temporary files"

test:
	@echo "Running unit tests..."
	@python3 -m unittest -v test.py

install:
	@echo ""
	@echo "To install $(APP_NAME) locally via pkgmgr, run:"
	@echo ""
	@echo "    pkgmgr install $(APP_NAME)"
	@echo ""
	@echo "If you prefer manual installation:"
	@echo "    sudo cp main.py /usr/local/bin/$(APP_NAME)"
	@echo "    sudo chmod +x /usr/local/bin/$(APP_NAME)"
	@echo ""

clean:
	@echo "Cleaning up..."
	@find . -type d -name '__pycache__' -exec rm -rf {} +
	@find . -type f -name '*.pyc' -delete
	@echo "Done."
