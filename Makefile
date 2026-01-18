# Makefile for Anamnesis - LLM Exploit Generation Evaluation System

# Load .env file if it exists
-include .env
export

.PHONY: help build-docker-bugfinder build-docker-bugfinder-cet docker-shell-bugfinder docker-shell-bugfinder-cet

# Default target - show help
help:
	@echo "Anamnesis - LLM Exploit Generation Evaluation System"
	@echo ""
	@echo "Available targets:"
	@echo "  build-docker-bugfinder      - Build the standard Docker image"
	@echo "  build-docker-bugfinder-cet  - Build the CET/Shadow Stack Docker image (Ubuntu-based)"
	@echo "  docker-shell-bugfinder      - Run interactive shell in standard container"
	@echo "  docker-shell-bugfinder-cet  - Run interactive shell in CET container"
	@echo ""
	@echo "Quick start:"
	@echo "  1. Copy .env.example to .env and add your API keys"
	@echo "  2. make build-docker-bugfinder"
	@echo "  3. python experiments/run_experiments.py -o ./results --experiment partial-relro-no-priors --model claude-opus-4-5-20251101 -n 1"
	@echo ""
	@echo "See README.md for full documentation."

# Build standard Docker image (Debian-based, for most experiments)
build-docker-bugfinder:
	@echo "Building standard bug-finder Docker image..."
	docker build -f Dockerfile.bugfinder -t evalrunner:bugfinder .
	@echo "Cleaning up dangling images..."
	-docker image prune -f
	@echo "Bug-finder Docker image built successfully"

# Build CET Docker image (Ubuntu 24.04-based, for Shadow Stack experiments)
build-docker-bugfinder-cet:
	@echo "Building Ubuntu-based CET bug-finder Docker image..."
	@echo "This image uses Ubuntu 24.04 for glibc with Shadow Stack support"
	docker build -f Dockerfile.bugfinder-cet -t evalrunner:bugfinder-cet .
	@echo "Cleaning up dangling images..."
	-docker image prune -f
	@echo "CET bug-finder Docker image built successfully"

# Development shell for standard image
docker-shell-bugfinder:
	@echo "Starting bug-finder development shell..."
	@mkdir -p test-output
	@chmod 777 test-output
	docker run -it --rm \
		-v $(PWD)/agents:/code/agents:rw \
		-v $(PWD)/test-output:/output:rw \
		-e ANTHROPIC_API_KEY=$(ANTHROPIC_API_KEY) \
		-e OPENAI_API_KEY=$(OPENAI_API_KEY) \
		evalrunner:bugfinder \
		bash

# Development shell for CET image
docker-shell-bugfinder-cet:
	@echo "Starting CET bug-finder development shell..."
	@mkdir -p test-output
	@chmod 777 test-output
	docker run -it --rm \
		-v $(PWD)/agents:/code/agents:rw \
		-v $(PWD)/test-output:/output:rw \
		-e ANTHROPIC_API_KEY=$(ANTHROPIC_API_KEY) \
		-e OPENAI_API_KEY=$(OPENAI_API_KEY) \
		evalrunner:bugfinder-cet \
		bash
