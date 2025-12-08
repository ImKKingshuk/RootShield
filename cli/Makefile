# RootShield CLI Makefile
# Author: @ImKKingshuk

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lcurl -ljson-c

TARGET = rootshield
SRCS = rootshield_cli.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRCS)
	@echo "Building RootShield CLI..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✓ Build complete: $(TARGET)"

clean:
	rm -f $(TARGET) $(OBJS)
	@echo "✓ Cleaned"

install: $(TARGET)
	@echo "Installing RootShield CLI..."
	sudo cp $(TARGET) /usr/local/bin/
	@echo "✓ Installed to /usr/local/bin/$(TARGET)"

uninstall:
	@echo "Uninstalling RootShield CLI..."
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "✓ Uninstalled"

help:
	@echo ""
	@echo "RootShield CLI Build System"
	@echo "==========================="
	@echo ""
	@echo "Targets:"
	@echo "  all       Build the CLI tool"
	@echo "  clean     Remove build artifacts"
	@echo "  install   Install to /usr/local/bin"
	@echo "  uninstall Remove from /usr/local/bin"
	@echo "  help      Show this help"
	@echo ""
	@echo "Dependencies:"
	@echo "  libcurl   - HTTP client library"
	@echo "  json-c    - JSON parsing library"
	@echo ""
	@echo "Install dependencies (Debian/Ubuntu):"
	@echo "  sudo apt install libcurl4-openssl-dev libjson-c-dev"
	@echo ""
	@echo "Install dependencies (macOS):"
	@echo "  brew install curl json-c"
	@echo ""
