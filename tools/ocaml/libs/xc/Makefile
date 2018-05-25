TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

CFLAGS += -I../mmap -I./ -I$(XEN_ROOT)/tools/libxc
OCAMLINCLUDE += -I ../mmap -I ../uuid -I $(XEN_ROOT)/tools/libxc

OBJS = xenctrl
INTF = xenctrl.cmi
LIBS = xenctrl.cma xenctrl.cmxa

LIBS_xenctrl = -L$(XEN_ROOT)/tools/libxc -lxenctrl -lxenguest

xenctrl_OBJS = $(OBJS)
xenctrl_C_OBJS = xenctrl_stubs

OCAML_LIBRARY = xenctrl

all: $(INTF) $(LIBS)

libs: $(LIBS)

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	ocamlfind remove -destdir $(OCAMLDESTDIR) xenctrl
	ocamlfind install -destdir $(OCAMLDESTDIR) -ldconf ignore xenctrl META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove -destdir $(OCAMLDESTDIR) xenctrl

include $(TOPLEVEL)/Makefile.rules
