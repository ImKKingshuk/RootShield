MODULE_NAME := RootShield
MODULE_OBJS := main.o exec_monitor.o file_monitor.o process_monitor.o
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := $(MODULE_OBJS)
ccflags-y += -Wno-declaration-after-statement

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean