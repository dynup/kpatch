KPATCH_BUILD = /lib/modules/$(shell uname -r)/build
KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(PWD)

obj-m += kpatch-patch.o

kpatch-patch-objs += kpatch-patch-hook.o kpatch.lds ../output.kpatch_gen

all: kpatch-patch.ko

kpatch-patch.ko:
	$(KPATCH_MAKE) kpatch-patch.ko

kpatch-patch-hook.o: kpatch-patch-hook.c
	$(KPATCH_MAKE) kpatch-patch-hook.o

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers
