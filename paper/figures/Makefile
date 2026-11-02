PYTHON ?= python3
XELATEX ?= xelatex

DATA_SCRIPTS = \
	scripts/fig04_cycles_vs_length.py \
	scripts/fig05_matcher_ablation.py \
	scripts/fig06_proof_feasibility.py \
	scripts/fig06b_proof_main.py \
	scripts/fig07_k_est.py \
	scripts/fig08_policy_disclosure.py \
	scripts/fig09_issuance_detection.py

CONCEPT_SRC = src/fig01_architecture.tex src/fig02_bhv_leakage.tex
CONCEPT_PDF = fig01_architecture.pdf fig02_bhv_leakage.pdf

.PHONY: all data concept png check page-budget clean rebuild

all: data concept check

data:
	@for s in $(DATA_SCRIPTS); do echo "== $$s"; $(PYTHON) $$s || exit 1; done

concept: $(CONCEPT_PDF) png

%.pdf: src/%.tex
	cd src && $(XELATEX) -interaction=nonstopmode -halt-on-error -output-directory=.. $(notdir $<)

png: $(CONCEPT_PDF)
	@for f in $(CONCEPT_PDF); do $(PYTHON) scripts/pdf2png.py $$f; done

check:
	$(PYTHON) scripts/check_fonts.py

page-budget:
	$(PYTHON) scripts/page_budget_test.py

clean:
	rm -f *.aux *.log *.out src/*.aux src/*.log

rebuild: clean all
