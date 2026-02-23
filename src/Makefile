ifneq ($(KERNELRELEASE),)
# Called from kernel build system
obj-m := lbd.o
lbd-y := lbd_main.o lbd_qcow2.o lz4/lz4.o

ccflags-y := -include $(M)/lz4_kcompat.h
CFLAGS_lz4/lz4.o := -Wno-deprecated-declarations -Wframe-larger-than=32768

else
# Called from command line
KDIR ?= /lib/modules/$(shell uname -r)/build

all: lbd.ko lbdctl

lbd.ko: lbd_main.c lbd.h lbd_qcow2.c lbd_qcow2.h lbd_qcow2_format.h cbor_enc.h cbor_dec.h lz4_kcompat.h lz4/lz4.c lz4/lz4.h
	$(MAKE) -C $(KDIR) M=$(CURDIR) KBUILD_MODPOST_WARN=1 modules

lbdctl: lbdctl.c lbd.h lbd_qcow2_format.h lz4/lz4.c lz4/lz4.h
	$(CC) -Wall -Wextra -O2 -o $@ lbdctl.c lz4/lz4.c

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	rm -f lbdctl

.PHONY: all clean

endif
