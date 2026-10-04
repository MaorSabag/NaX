# NaX src_server/Makefile
# Builds extender plugins and deploys to Server/extenders/.
# Usage:  make -C src_server
#         make -C src_server SERVER_DIR=/path/to/Server
#
# SERVER_DIR, GO, and GOEXPERIMENT are overridable (setup_nax.sh passes them).
# GOEXPERIMENT must match the flags used to build adaptixserver.
# Auto-detect with:  go version Server/adaptixserver

NAX_ROOT    := $(shell cd .. && pwd)
REPO_ROOT   := $(shell cd ../.. && pwd)
SERVER_DIR  ?= $(REPO_ROOT)/Server
AGENT_DIR   := $(NAX_ROOT)/src_server/agent_nonameax
LISTENER_DIR     := $(NAX_ROOT)/src_server/listener_nonameax_http
LISTENER_SMB_DIR := $(NAX_ROOT)/src_server/listener_nonameax_smb
SERVICE_DIR      := $(NAX_ROOT)/src_server/service_nax_store
DEPLOY_AGENT        := $(SERVER_DIR)/extenders/agent_nonameax
DEPLOY_LISTENER     := $(SERVER_DIR)/extenders/listener_nonameax_http
DEPLOY_LISTENER_SMB := $(SERVER_DIR)/extenders/listener_nonameax_smb
DEPLOY_SERVICE      := $(SERVER_DIR)/extenders/service_nax_store

GO           ?= go
GOEXPERIMENT ?=

# Only set GOEXPERIMENT env var if non-empty
ifdef GOEXPERIMENT
  GO_ENV := GOEXPERIMENT=$(GOEXPERIMENT)
else
  GO_ENV :=
endif

.PHONY: all clean test verify-sync agent listener listener-smb service

all: agent listener listener-smb service

agent:
	@echo "  BUILD  agent_nonameax.so"
	@cd $(AGENT_DIR) && $(GO_ENV) $(GO) build -buildmode=plugin \
		-o $(DEPLOY_AGENT)/agent_nonameax.so .
	@cp $(AGENT_DIR)/ax_config.axs $(DEPLOY_AGENT)/ax_config.axs
	@cp $(AGENT_DIR)/config.yaml   $(DEPLOY_AGENT)/config.yaml
	@cp -r $(AGENT_DIR)/pe_templates $(DEPLOY_AGENT)/pe_templates
	@echo "  DEPLOY $(DEPLOY_AGENT)/"

listener:
	@echo "  BUILD  listener_nonameax_http.so"
	@cd $(LISTENER_DIR) && $(GO_ENV) $(GO) build -buildmode=plugin \
		-o $(DEPLOY_LISTENER)/listener_nonameax_http.so .
	@cp $(LISTENER_DIR)/ax_config.axs $(DEPLOY_LISTENER)/ax_config.axs
	@cp $(LISTENER_DIR)/config.yaml   $(DEPLOY_LISTENER)/config.yaml
	@echo "  DEPLOY $(DEPLOY_LISTENER)/"

listener-smb:
	@echo "  BUILD  listener_nonameax_smb.so"
	@mkdir -p $(DEPLOY_LISTENER_SMB)
	@cd $(LISTENER_SMB_DIR) && $(GO_ENV) $(GO) build -buildmode=plugin \
		-o $(DEPLOY_LISTENER_SMB)/listener_nonameax_smb.so .
	@cp $(LISTENER_SMB_DIR)/ax_config.axs $(DEPLOY_LISTENER_SMB)/ax_config.axs
	@cp $(LISTENER_SMB_DIR)/config.yaml   $(DEPLOY_LISTENER_SMB)/config.yaml
	@echo "  DEPLOY $(DEPLOY_LISTENER_SMB)/"

service:
	@echo "  BUILD  nax_store.so"
	@mkdir -p $(DEPLOY_SERVICE)
	@cd $(SERVICE_DIR) && $(GO_ENV) $(GO) build -buildmode=plugin \
		-ldflags="-s -w" -o $(DEPLOY_SERVICE)/nax_store.so .
	@cp $(SERVICE_DIR)/ax_config.axs $(DEPLOY_SERVICE)/ax_config.axs
	@cp $(SERVICE_DIR)/config.yaml   $(DEPLOY_SERVICE)/config.yaml
	@echo "  DEPLOY $(DEPLOY_SERVICE)/"

test:
	@echo "  TEST   agent_nonameax"
	@cd $(AGENT_DIR)    && $(GO) test ./...
	@echo "  TEST   listener_nonameax_http"
	@cd $(LISTENER_DIR) && $(GO) test ./...

verify-sync:
	@diff -q $(AGENT_DIR)/pl_wire.go $(LISTENER_DIR)/pl_wire.go || \
		(echo "ERROR: pl_wire.go out of sync" && exit 1)
	@diff -q $(AGENT_DIR)/pl_crypto.go $(LISTENER_DIR)/pl_crypto.go || \
		(echo "ERROR: pl_crypto.go out of sync" && exit 1)
	@diff -q $(AGENT_DIR)/pl_wire_test.go $(LISTENER_DIR)/pl_wire_test.go || \
		(echo "ERROR: pl_wire_test.go out of sync" && exit 1)
	@diff -q $(AGENT_DIR)/pl_crypto_test.go $(LISTENER_DIR)/pl_crypto_test.go || \
		(echo "ERROR: pl_crypto_test.go out of sync" && exit 1)
	@echo "  SYNC   All synced files are identical"

clean:
	@rm -f $(DEPLOY_AGENT)/agent_nonameax.so
	@rm -f $(DEPLOY_LISTENER)/listener_nonameax_http.so
	@rm -f $(DEPLOY_LISTENER_SMB)/listener_nonameax_smb.so
	@rm -f $(DEPLOY_SERVICE)/nax_store.so
	@echo "  CLEAN  done"
