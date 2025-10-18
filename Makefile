# RootShield v3.0 - Enhanced Build System
# ======================================
#
# This Makefile builds the complete RootShield v3.0 system including:
# - Kernel module with plugin architecture
# - User-space API server
# - Web dashboard
# - Additional tools

# Version information
VERSION_MAJOR := 3
VERSION_MINOR := 0
VERSION_PATCH := 0
VERSION := $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)

# Build configuration
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Directories
SRC_DIR := src
CORE_DIR := $(SRC_DIR)/core
PLUGINS_DIR := $(SRC_DIR)/plugins
INCLUDE_DIR := $(SRC_DIR)/include
API_DIR := api
WEB_DIR := web
TOOLS_DIR := tools

# Kernel module configuration
MODULE_NAME := rootshield
obj-m := $(MODULE_NAME).o

# Core source files
CORE_SRCS := $(wildcard $(CORE_DIR)/*.c)
CORE_OBJS := $(patsubst %.c,%.o,$(notdir $(CORE_SRCS)))

# Plugin source files
PLUGIN_SRCS := $(wildcard $(PLUGINS_DIR)/*.c)
PLUGIN_OBJS := $(patsubst %.c,%.o,$(notdir $(PLUGIN_SRCS)))

# All kernel objects
$(MODULE_NAME)-objs := $(CORE_OBJS) $(PLUGIN_OBJS)

# Compiler flags
ccflags-y += -I$(INCLUDE_DIR)
ccflags-y += -DROOTSHIELD_VERSION_MAJOR=$(VERSION_MAJOR)
ccflags-y += -DROOTSHIELD_VERSION_MINOR=$(VERSION_MINOR)
ccflags-y += -DROOTSHIELD_VERSION_PATCH=$(VERSION_PATCH)
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wall -Werror
ccflags-y += -O2

# User-space build flags
CC := gcc
CFLAGS := -Wall -Werror -O2 -I$(INCLUDE_DIR)
LDFLAGS :=

# Dependencies for user-space programs
LIBMICROHTTPD := $(shell pkg-config --libs libmicrohttpd 2>/dev/null || echo "-lmicrohttpd")
LIBJSON := $(shell pkg-config --libs json-c 2>/dev/null || echo "-ljson-c")
LIBSQLITE := -lsqlite3
LIBPTHREAD := -lpthread

# Build targets
.PHONY: all kernel user api web tools install clean distclean help

all: kernel user

kernel: $(MODULE_NAME).ko

user: api web tools

api: $(API_DIR)/rootshield_api

web: $(WEB_DIR)/dashboard.html

tools: $(TOOLS_DIR)/rootshield_cli

# Kernel module build
$(MODULE_NAME).ko: $(CORE_SRCS) $(PLUGIN_SRCS)
	@echo "Building RootShield kernel module v$(VERSION)..."
	make -C $(KERNEL_DIR) M=$(PWD) modules
	@echo "Kernel module built successfully"

# API server build
$(API_DIR)/rootshield_api: $(API_DIR)/rootshield_api.c
	@echo "Building API server..."
	$(CC) $(CFLAGS) -o $@ $< $(LIBMICROHTTPD) $(LIBJSON) $(LIBSQLITE) $(LIBPTHREAD) $(LDFLAGS)
	@echo "API server built successfully"

# CLI tool build
$(TOOLS_DIR)/rootshield_cli: $(TOOLS_DIR)/rootshield_cli.c
	@echo "Building CLI tool..."
	$(CC) $(CFLAGS) -o $@ $< $(LIBJSON) $(LDFLAGS)
	@echo "CLI tool built successfully"

# Installation
install: all
	@echo "Installing RootShield v$(VERSION)..."
	# Install kernel module
	sudo insmod $(MODULE_NAME).ko
	# Install API server
	sudo cp $(API_DIR)/rootshield_api /usr/local/bin/
	sudo cp $(TOOLS_DIR)/rootshield_cli /usr/local/bin/
	# Install web dashboard
	sudo mkdir -p /var/www/html/rootshield
	sudo cp $(WEB_DIR)/* /var/www/html/rootshield/
	@echo "Installation completed"

# Uninstall
uninstall:
	@echo "Uninstalling RootShield..."
	-sudo rmmod $(MODULE_NAME)
	-sudo rm -f /usr/local/bin/rootshield_api
	-sudo rm -f /usr/local/bin/rootshield_cli
	-sudo rm -rf /var/www/html/rootshield
	@echo "Uninstallation completed"

# Development targets
debug: CFLAGS += -DDEBUG -g
debug: all

# Testing targets
test-kernel: kernel
	@echo "Testing kernel module..."
	sudo insmod $(MODULE_NAME).ko
	@echo "Module loaded, checking dmesg..."
	dmesg | tail -20
	@sleep 2
	sudo rmmod $(MODULE_NAME)
	@echo "Kernel module test completed"

test-api: api
	@echo "Testing API server..."
	./$(API_DIR)/rootshield_api &
	@sleep 3
	curl -s http://localhost:8080/api/v1/status | head -5
	kill %1
	@echo "API server test completed"

# Cleaning
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f $(API_DIR)/rootshield_api
	rm -f $(TOOLS_DIR)/rootshield_cli
	rm -f *.o *.ko *.mod.c .*.cmd Module.symvers modules.order
	rm -rf .tmp_versions

distclean: clean
	rm -f *.tar.gz
	rm -rf dist/

# Distribution package
dist: all
	mkdir -p dist/rootshield-$(VERSION)
	cp -r src include api web tools Makefile README.md LICENSE dist/rootshield-$(VERSION)/
	cd dist && tar czf ../rootshield-$(VERSION).tar.gz rootshield-$(VERSION)
	rm -rf dist/
	@echo "Distribution package created: rootshield-$(VERSION).tar.gz"

# Help target
help:
	@echo "RootShield v$(VERSION) Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all          - Build everything (kernel + user-space)"
	@echo "  kernel       - Build kernel module only"
	@echo "  user         - Build user-space components only"
	@echo "  api          - Build API server only"
	@echo "  web          - Build web dashboard only"
	@echo "  tools        - Build CLI tools only"
	@echo "  install      - Install all components"
	@echo "  uninstall    - Uninstall all components"
	@echo "  clean        - Clean build artifacts"
	@echo "  distclean    - Clean everything including distribution files"
	@echo "  test-kernel  - Test kernel module loading/unloading"
	@echo "  test-api     - Test API server functionality"
	@echo "  dist         - Create distribution tarball"
	@echo "  debug        - Build with debug symbols"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Configuration:"
	@echo "  KERNEL_DIR   - Kernel build directory (default: /lib/modules/`uname -r`/build)"
	@echo ""
	@echo "Examples:"
	@echo "  make all                    # Build everything"
	@echo "  make KERNEL_DIR=/path/to/kernel install  # Build for specific kernel"
	@echo "  make test-kernel test-api   # Run all tests"

# Dependencies check
deps-check:
	@echo "Checking build dependencies..."
	@command -v $(CC) >/dev/null 2>&1 || { echo "Error: $(CC) not found"; exit 1; }
	@pkg-config --exists libmicrohttpd 2>/dev/null || echo "Warning: libmicrohttpd not found (needed for API server)"
	@pkg-config --exists json-c 2>/dev/null || echo "Warning: json-c not found (needed for API server)"
	@command -v sqlite3 >/dev/null 2>&1 || echo "Warning: sqlite3 not found (needed for database)"
	@if [ ! -d "$(KERNEL_DIR)" ]; then echo "Error: Kernel build directory not found: $(KERNEL_DIR)"; exit 1; fi
	@echo "Dependencies check completed"

# Default target
.DEFAULT_GOAL := all