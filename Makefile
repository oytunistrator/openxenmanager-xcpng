.PHONY: all install test run clean venv

all: install

venv:
	python3 -m venv venv
	source venv/bin/activate && pip install -e .

install:
	pip install -e .

test:
	source venv/bin/activate && python -m pytest

run:
	source venv/bin/activate && ./openxenmanager

clean:
	rm -rf build dist *.egg-info venv
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +