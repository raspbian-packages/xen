include $(XEN_ROOT)/tools/Rules.mk

FSDIR := $(LIBEXEC_LIB)/xenfsimage
CFLAGS += -Wno-unknown-pragmas -I$(XEN_ROOT)/tools/libfsimage/common/ -DFSIMAGE_FSDIR=\"$(FSDIR)\"
CFLAGS += -D_GNU_SOURCE
LDFLAGS += -L../common/
LDFLAGS += $(call LDFLAGS_RPATH,../..)

PIC_OBJS = $(patsubst %.c,%.opic,$(LIB_SRCS-y))

clean distclean::
	rm -f $(PIC_OBJS) $(TARGETS) $(DEPS_RM)
