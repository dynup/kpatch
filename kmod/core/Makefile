# make rules
KPATCH_BUILD ?= /lib/modules/$(shell uname -r)/source
THISDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

ifeq ($(wildcard $(KPATCH_BUILD)),)
$(error $(KPATCH_BUILD) doesn\'t exist.  Try installing the kernel-devel-$(shell uname -r) RPM.)
endif

KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(THISDIR)

kpatch.ko: core.c trampoline.S
	$(KPATCH_MAKE) kpatch.ko

all: kpatch.ko

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers


# kbuild rules
obj-m := kpatch.o
kpatch-y := core.o trampoline.o
