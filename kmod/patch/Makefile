KPATCH_NAME ?= patch
KPATCH_BUILD ?= /lib/modules/$(shell uname -r)/build
KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(PWD)

obj-m += kpatch-$(KPATCH_NAME).o

kpatch-$(KPATCH_NAME)-objs += kpatch-patch-hook.o kpatch.lds output.o

all: kpatch-$(KPATCH_NAME).ko

kpatch-$(KPATCH_NAME).ko:
	$(KPATCH_MAKE) kpatch-$(KPATCH_NAME).ko

kpatch-patch-hook.o: kpatch-patch-hook.c
	$(KPATCH_MAKE) kpatch-patch-hook.o

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers
