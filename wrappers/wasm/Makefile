PKG_NAME ?= $(shell npm pkg get name | tr -d '"')
PKG_VERSION ?= $(shell npm pkg get version | tr -d '"')
PKG_MAIN ?= $(shell npm pkg get main | tr -d '"')
PKG_TYPES ?= $(shell npm pkg get types | tr -d '"')
WASM_TARGET ?= web
FEATURES ?=
DEV ?=

ifeq ($(strip $(FEATURES)),)
    FEATURES_OPTION =
else
    FEATURES_OPTION = -- --features $(FEATURES)
endif

ifeq ($(DEV), true)
    BUILD_MODE = --dev
    PKG_VERSION = $(shell npm pkg get version | tr -d '"')-dev
endif

ifndef PROJECT_DIR
PROJECT_DIR := $(shell git rev-parse --show-toplevel)
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Darwin)
    SED_INPLACE = sed -i "" -E
else
    SED_INPLACE = sed -i -r
endif

WASM_DIR_NAME := wasm
WASM_DIR := $(PROJECT_DIR)/wrappers/$(WASM_DIR_NAME)

WASM_PKG_DIR_NAME := pkg
WASM_PKG_DIR := $(WASM_DIR)/$(WASM_PKG_DIR_NAME)

TYPES_DIR := $(PROJECT_DIR)/wrappers/types
TS_MODULE := esm
TYPES_TS_CONFIG := tsconfig.$(TS_MODULE).json

.PHONY: all \
		pkg_clean build install publish clean

all: build

pkg_clean:
	rm -rf $(WASM_PKG_DIR)

build: $(WASM_DIR) pkg_clean
	cd $<
	RUSTFLAGS="--cfg getrandom_backend=\"wasm_js\"" wasm-pack build $(BUILD_MODE) --target $(WASM_TARGET) --out-name index $(FEATURES_OPTION)
	$(SED_INPLACE) "s|\"name\": \"[^\"]*\"|\"name\": \"$(PKG_NAME)\"|g" $(WASM_PKG_DIR)/package.json
	$(SED_INPLACE) "s|\"version\": \"[^\"]*\"|\"version\": \"$(PKG_VERSION)\"|g" $(WASM_PKG_DIR)/package.json
	$(SED_INPLACE) "s|\"main\": \"[^\"]*\"|\"main\": \"$(PKG_MAIN)\"|g" $(WASM_PKG_DIR)/package.json
	$(SED_INPLACE) "s|\"types\": \"[^\"]*\"|\"types\": \"$(PKG_TYPES)\"|g" $(WASM_PKG_DIR)/package.json
	$(SED_INPLACE) "/\"files\": \\[/,/\\],/d" $(WASM_PKG_DIR)/package.json
	npx tsc -p $(TYPES_DIR)/$(TYPES_TS_CONFIG) && mv $(TYPES_DIR)/dist/$(TS_MODULE) $(WASM_PKG_DIR)/dist
	node scripts/add-import-line-$(TS_MODULE).mjs
	node scripts/add-export-line-$(TS_MODULE).mjs
	npx tsc -p $(TYPES_TS_CONFIG)

install: $(WASM_PKG_DIR)
	cd $< && npm install .

pack: $(WASM_PKG_DIR)
	cd $(WASM_DIR)
	wasm-pack pack

clean: $(WASM_DIR) pkg_clean
	cd $< && cargo clean
