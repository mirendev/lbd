ifneq ($(KERNELRELEASE),)
# Called from kernel build system
obj-m := lbd_mod.o
lbd_mod-y := lbd.o lz4/lz4.o

ccflags-y := -include $(M)/lz4_kcompat.h
CFLAGS_lz4/lz4.o := -Wno-deprecated-declarations -Wframe-larger-than=32768

else
# Called from command line
KDIR ?= /lib/modules/$(shell uname -r)/build

all: lbd_mod.ko lbdctl

lbd_mod.ko: lbd.c lbd.h cbor_enc.h lz4_kcompat.h lz4/lz4.c lz4/lz4.h
	$(MAKE) -C $(KDIR) M=$(PWD) KBUILD_MODPOST_WARN=1 modules

lbdctl: lbdctl.c lbd.h lz4/lz4.c lz4/lz4.h
	$(CC) -Wall -Wextra -O2 -o $@ lbdctl.c lz4/lz4.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f lbdctl

.PHONY: all clean

endif
