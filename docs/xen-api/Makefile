#!/usr/bin/make -f

XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/Config.mk
include $(XEN_ROOT)/docs/Docs.mk


TEX := $(wildcard *.tex)
PDFEPS := $(patsubst %.eps,%.pdf,$(wildcard *.eps))
PDFDOT := $(patsubst %.dot,%.pdf,$(wildcard *.dot))

.PHONY: all
all: build

.PHONY: build
build: xenapi.pdf

install:
	$(INSTALL_DIR) $(DESTDIR)$(DOCDIR)

	[ -e xenapi.pdf ] && cp xenapi.pdf $(DESTDIR)$(DOCDIR) || true

xenapi.pdf: $(TEX) $(PDFEPS) $(PDFDOT)
	$(PDFLATEX) xenapi.tex
	$(PDFLATEX) xenapi.tex
	rm -f *.aux *.log

%.pdf: %.eps
	$(EPSTOPDF) $<

%.pdf: %.dot
	$(DOT) -Tpdf $< >$@

xenapi-datamodel-graph.eps: xenapi-datamodel-graph.dot
	$(NEATO) -Goverlap=false -Tps $< >$@

.PHONY: clean
clean:
	rm -f *.pdf *.ps *.dvi *.aux *.log *.out $(EPSDOT)
