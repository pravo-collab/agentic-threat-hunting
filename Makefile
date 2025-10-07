.PHONY: install test run clean format lint help

help:
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make test       - Run tests"
	@echo "  make run        - Run the application"
	@echo "  make clean      - Clean up generated files"
	@echo "  make format     - Format code with black"
	@echo "  make lint       - Lint code with flake8"

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v --cov=src --cov-report=html

run:
	python src/main.py

run-sample:
	python src/main.py --input data/sample_logs.json

run-phishing:
	python src/main.py --input data/phishing_event.json

run-intrusion:
	python src/main.py --input data/intrusion_event.json

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf logs/*.log

format:
	black src/ tests/

lint:
	flake8 src/ tests/ --max-line-length=120

setup-env:
	cp .env.example .env
	@echo "Please edit .env file with your API keys"
