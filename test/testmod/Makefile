BUILD ?= /lib/modules/$(shell uname -r)/build

testmod.ko: testmod_drv.c
	patch < patch
	KCFLAGS="-ffunction-sections -fdata-sections" $(MAKE) -C $(BUILD) M=$(PWD) testmod.ko
	strip --keep-file-symbols -d testmod_drv.o
	cp testmod_drv.o testmod_drv.o.patched
	patch -R < patch
	KCFLAGS="-ffunction-sections -fdata-sections" $(MAKE) -C $(BUILD) M=$(PWD) testmod.ko
	strip --keep-file-symbols -d testmod_drv.o
	cp testmod_drv.o testmod_drv.o.orig
	$(MAKE) -C $(BUILD) M=$(PWD) clean
	$(MAKE) -C $(BUILD) M=$(PWD) testmod.ko

all: testmod.ko

clean:
	$(MAKE) -C $(BUILD) M=$(PWD) clean
	rm *.orig *.patched

# kbuild rules
obj-m := testmod.o
testmod-y := testmod_drv.o
