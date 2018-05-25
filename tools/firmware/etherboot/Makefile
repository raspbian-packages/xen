
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk
include Config

ifeq ($(GIT_HTTP),y)
IPXE_GIT_URL := http://git.ipxe.org/ipxe.git
else
IPXE_GIT_URL := git://git.ipxe.org/ipxe.git
endif

IPXE_GIT_TAG := v1.0.0

IPXE_TARBALL_URL := $(XEN_EXTFILES_URL)/ipxe-git-$(IPXE_GIT_TAG).tar.gz

ROMS = $(addprefix /usr/lib/ipxe/, $(addsuffix .rom, $(NICS)))

.NOTPARALLEL:

.PHONY: all
all: eb-roms.h

eb-roms.h: $(ROMS)
	cat $^ | ../hvmloader/mkhex etherboot >$@

.PHONY: clean
clean:
	rm -rf *~ eb-roms.h

.PHONY: distclean
distclean: clean
