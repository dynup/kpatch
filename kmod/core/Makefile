KPATCH_BUILD ?= /usr/lib/modules/$(shell uname -r)/build
KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(PWD)

obj-m := kpatch.o
kpatch-y := core.o trampoline.o

kpatch.ko: core.c trampoline.S
	$(KPATCH_MAKE) kpatch.ko

all: kpatch.ko

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers
