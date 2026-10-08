.PHONY: help hooks start-db stop clean wait-db fmt-check vet test fuzz verify

SHELL := /bin/bash

GO_IMAGE ?= golang:1.27.1
GO_TEST_ARGS ?= -race -count=1 ./...
FUZZTIME ?= 20s
GO_RUN = docker run --rm -v "$(CURDIR):/src" -w /src \
	-v authkit_go_mod_cache:/go/pkg/mod -v authkit_go_build_cache:/root/.cache/go-build \
	-e GOFLAGS=-buildvcs=false -e AUTHKIT_REQUIRE_DB=1 \
	-e AUTHKIT_PG='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' \
	--network container:authkit_db $(GO_IMAGE)

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-10s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

hooks: ## Point git at .githooks; pre-push runs make verify
	@git config core.hooksPath .githooks

start-db: ## Start the throwaway Postgres 17 on localhost:5446
	@docker compose up -d db
	@$(MAKE) --no-print-directory wait-db

stop: ## Stop it and keep its data
	@docker compose down

clean: ## Stop it and delete its volume, every template and test database included
	@docker compose down -v

wait-db: ## Wait until Postgres is healthy
	@for i in $$(seq 1 60); do \
		if [ "$$(docker inspect authkit_db --format '{{.State.Health.Status}}' 2>/dev/null)" = healthy ]; then exit 0; fi; \
		sleep 1; \
	done; echo "postgres did not become healthy: run make start-db" >&2; exit 1

fmt-check: ## Fail when gofmt would change a Go file
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt would change:" >&2; echo "$$out" >&2; exit 1; fi

vet: wait-db ## go vet every package in the Go container
	@$(GO_RUN) go vet ./...

test: wait-db fmt-check ## Every test with -race, against the throwaway database (GO_TEST_ARGS narrows it; quote a -run pattern)
	@$(GO_RUN) sh -c 'go test $(subst ','\'',$(GO_TEST_ARGS))'

fuzz: wait-db ## Each fuzz target for FUZZTIME
	@$(GO_RUN) sh -c 'go test ./transport/bearer -run=^$$ -fuzz=^FuzzParse$$ -fuzztime=$(FUZZTIME) && go test ./transport/bearer -run=^$$ -fuzz=^FuzzFromHeader$$ -fuzztime=$(FUZZTIME)'

verify: fmt-check vet test fuzz ## The pre-push gate

.DEFAULT_GOAL := help
