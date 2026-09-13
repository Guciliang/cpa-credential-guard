PLUGIN_NAME := cpa-credential-guard
UNAME_S := $(shell uname -s)
ifeq ($(OS),Windows_NT)
  PLUGIN_EXT := dll
else ifeq ($(UNAME_S),Darwin)
  PLUGIN_EXT := dylib
else
  PLUGIN_EXT := so
endif

.PHONY: build test vet fmt clean

build:
	mkdir -p bin
	CGO_ENABLED=1 go build -buildmode=c-shared -o bin/$(PLUGIN_NAME).$(PLUGIN_EXT) .
	test -f bin/$(PLUGIN_NAME).h && rm -f bin/$(PLUGIN_NAME).h || true

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*' -not -path './bin/*' -not -path './.cpa-integration-test/*')

clean:
	rm -rf bin
