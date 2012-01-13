TOP = $(shell pwd)
VE = virtualenv
PY = $(TOP)/bin/python
EZ = $(TOP)/bin/easy_install

.PHONY: build build-egg

build: 
	$(VE) --no-site-packages .

build-egg:
	$(PY) setup.py bdist_egg -dist-dir dist
