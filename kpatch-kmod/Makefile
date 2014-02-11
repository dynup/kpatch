KPATCH_BUILD = /home/sjennings/projects/linux
KPATCH_OBJ = /home/sjennings/projects/obj
KPATCH_MODULES = $(PWD)
KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) O=$(KPATCH_OBJ) M=$(KPATCH_MODULES)

obj-m := kpatch.o
kpatch-y := base.o trampoline.o

kpatch.ko: base.c trampoline.S
	$(KPATCH_MAKE) kpatch.ko

all: kpatch.ko

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers
