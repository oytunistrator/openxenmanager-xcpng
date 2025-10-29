.PHONY: all install test run clean

all: install

install:
	pip install -e .

test:
	python -m pytest

run:
	python -m oxm.main

clean:
	rm -rf build dist *.egg-info
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +