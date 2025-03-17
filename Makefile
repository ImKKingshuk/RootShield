#  RootShield
#  Author: @ImKKingshuk

MODULE_NAME := RootShield
MODULE_OBJS := main.o exec_monitor.o file_monitor.o process_monitor.o network_monitor.o syscall_monitor.o memory_monitor.o module_monitor.o utils.o
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := $(MODULE_OBJS)
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wall -Werror

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean