PKG_NAME ?= agent-sdk
PKG_VERSION ?= 0.6.0
WASM_TARGET ?= nodejs

ifndef PROJECT_DIR
PROJECT_DIR := $(shell git rev-parse --show-toplevel)
endif

WASM_DIR_NAME := wasm
WASM_DIR := $(PROJECT_DIR)/wrappers/$(WASM_DIR_NAME)

WASM_PKG_DIR_NAME := pkg
WASM_PKG_DIR := $(WASM_DIR)/$(WASM_PKG_DIR_NAME)

TYPES_DIR := $(PROJECT_DIR)/wrappers/types

.PHONY: all \
		pkg_clean build install publish clean

all: build

pkg_clean:
	rm -rf $(WASM_PKG_DIR)

build: $(WASM_DIR) pkg_clean
	cd $<
	wasm-pack build --target $(WASM_TARGET) --out-name binary
	sed -i -r "s/\"name\": \"[^\"]*\"/\"name\": \"$(PKG_NAME)\"/g" $(WASM_PKG_DIR_NAME)/package.json
	sed -i -r "s/\"version\": \"[^\"]*\"/\"version\": \"$(PKG_VERSION)\"/g" $(WASM_PKG_DIR_NAME)/package.json
	sed -i -r "s/\"main\": \"[^\"]*\"/\"main\": \"index.js\"/g" $(WASM_PKG_DIR_NAME)/package.json
	sed -i -r "s/\"types\": \"[^\"]*\"/\"types\": \"index.d.ts\"/g" $(WASM_PKG_DIR_NAME)/package.json
	npx tsc -p $(TYPES_DIR) && mv $(TYPES_DIR)/dist $(WASM_PKG_DIR)/dist
	node scripts/add-import-line.mjs
	npx tsc



install: $(WASM_PKG_DIR)
	cd $< && npm install .

pack: $(WASM_PKG_DIR)
	cd $(WASM_DIR)
	wasm-pack pack

clean: $(WASM_DIR) pkg_clean
	cd $< && cargo clean
