#  RootShield
#  Author: @ImKKingshuk

# Kernel module configuration
MODULE_NAME := RootShield
SRC_DIR := src
CORE_DIR := $(SRC_DIR)/core
MONITORS_DIR := $(SRC_DIR)/monitors
UTILS_DIR := $(SRC_DIR)/utils

# Source files
CORE_SRCS := $(wildcard $(CORE_DIR)/*.c)
MONITORS_SRCS := $(wildcard $(MONITORS_DIR)/*.c)
UTILS_SRCS := $(wildcard $(UTILS_DIR)/*.c)

# Object files
MODULE_OBJS := $(patsubst %.c,%.o,$(notdir $(CORE_SRCS) $(MONITORS_SRCS) $(UTILS_SRCS)))

# Kernel module configuration
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := $(MODULE_OBJS)

# Compiler flags
ccflags-y += -I$(SRC_DIR)/include
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wall -Werror

# Build targets
all: module client

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

client:
	$(MAKE) -C client

clean: module_clean client_clean

module_clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

client_clean:
	$(MAKE) -C client clean

.PHONY: all module client clean module_clean client_clean