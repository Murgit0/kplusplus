PYTHON ?= python3
KPP ?= $(PYTHON) kpp.py

.PHONY: smoke test test-interpreter test-security build-binary

smoke:
	$(KPP) syntax.kpp

test: test-interpreter test-security

test-interpreter:
	./tests_interpreter_extensive.sh

test-security:
	./tests_security.sh

build-binary:
	.venv/bin/python -m PyInstaller --onefile --name kpp kpp.py
