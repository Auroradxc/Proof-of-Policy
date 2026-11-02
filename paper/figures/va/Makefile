PYTHON ?= python3
XELATEX ?= xelatex

TIKZ_SRC = src/va01_deployment_trust.tex src/va02_certificate_lifecycle.tex
TIKZ_PDF = va01_deployment_trust.pdf va02_certificate_lifecycle.pdf
ALL_PDF = $(TIKZ_PDF) va03_comparison_matrix.pdf va04_claim_evidence.pdf

.PHONY: all tikz data png check placement clean

all: tikz data png check

tikz: $(TIKZ_PDF)

%.pdf: src/%.tex
	cd src && $(XELATEX) -interaction=nonstopmode -halt-on-error -output-directory=.. $(notdir $<)

data:
	$(PYTHON) scripts/va03_comparison_matrix.py
	$(PYTHON) scripts/va04_claim_evidence.py

png: $(TIKZ_PDF)
	@for f in $(TIKZ_PDF); do $(PYTHON) ../scripts/pdf2png.py $$f; done

check:
	$(PYTHON) scripts/check_fonts.py

placement:
	$(PYTHON) scripts/placement_test.py

clean:
	rm -f *.aux *.log *.out src/*.aux src/*.log
	rm -rf integration-test/figures
	rm -f integration-test/*.aux integration-test/*.log integration-test/*.out
	rm -f integration-test/*.pdf integration-test/*.tex
