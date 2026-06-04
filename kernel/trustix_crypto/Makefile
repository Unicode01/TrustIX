ifneq ($(KERNELRELEASE),)
obj-m += trustix_crypto.o
ifeq ($(DEVICE_ONLY),1)
ccflags-y += -DTRUSTIX_DEVICE_ONLY=1
endif
else

KDIR ?= /lib/modules/$(shell uname -r)/build
KBUILD_ARGS := M=$(CURDIR)
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
KDIR_NOSLASH := $(patsubst %/,%,$(KDIR))
KDIR_MODULES_KERNELRELEASE := $(notdir $(patsubst %/source,%,$(patsubst %/build,%,$(KDIR_NOSLASH))))
TARGET_KERNELRELEASE ?= $(if $(filter /lib/modules/%/build /lib/modules/%/source,$(KDIR_NOSLASH)),$(KDIR_MODULES_KERNELRELEASE),$(shell $(MAKE) -s -C $(KDIR) kernelrelease 2>/dev/null || uname -r))
.DEFAULT_GOAL := all
ifneq ($(ARCH),)
KBUILD_ARGS += ARCH=$(ARCH)
endif
ifneq ($(CROSS_COMPILE),)
KBUILD_ARGS += CROSS_COMPILE=$(CROSS_COMPILE)
endif

prepare-btf-base:
	@if [ ! -r "$(KDIR)/vmlinux" ] && [ -r "$(VMLINUX_BTF)" ]; then \
		ln -sfn "$(VMLINUX_BTF)" "$(KDIR)/vmlinux" 2>/dev/null || true; \
	fi

all: prepare-btf-base
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) modules

device-only: prepare-btf-base
	$(MAKE) DEVICE_ONLY=1 -C $(KDIR) $(KBUILD_ARGS) modules

clean:
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) clean

install: all
	install -d $(INSTALL_MOD_PATH)/lib/modules/$(TARGET_KERNELRELEASE)/extra
	install -m 0644 trustix_crypto.ko $(INSTALL_MOD_PATH)/lib/modules/$(TARGET_KERNELRELEASE)/extra/trustix_crypto.ko
	@if [ -n "$(INSTALL_MOD_PATH)" ]; then \
		depmod -a -b "$(INSTALL_MOD_PATH)" "$(TARGET_KERNELRELEASE)"; \
	else \
		depmod -a "$(TARGET_KERNELRELEASE)"; \
	fi

load: all
	insmod ./trustix_crypto.ko

unload:
	-rmmod trustix_crypto

.PHONY: all device-only clean install load unload prepare-btf-base
endif
