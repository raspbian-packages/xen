TOPLEVEL=$(CURDIR)/../..
XEN_ROOT=$(TOPLEVEL)/../..
include $(TOPLEVEL)/common.make

OBJS = xenlight
INTF = xenlight.cmi
LIBS = xenlight.cma xenlight.cmxa

xenlight_OBJS = $(OBJS)
xenlight_C_OBJS = xenlight_stubs

OCAML_LIBRARY = xenlight

all: $(INTF) $(LIBS)

libs: $(LIBS)

.PHONY: install
install: $(LIBS) META
	mkdir -p $(OCAMLDESTDIR)
	ocamlfind remove -destdir $(OCAMLDESTDIR) xenlight
	ocamlfind install -destdir $(OCAMLDESTDIR) -ldconf ignore xenlight META $(INTF) $(LIBS) *.a *.so *.cmx

.PHONY: uninstall
uninstall:
	ocamlfind remove -destdir $(OCAMLDESTDIR) xenlight

include $(TOPLEVEL)/Makefile.rules
