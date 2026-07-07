# Makefile - agent_nonameax extender plugin
#
# GOEXPERIMENT must match the flags used to build adaptixserver; the Go plugin
# loader checks internal/goexperiment compatibility and rejects mismatches.
# Inspect the server binary with:
#   strings Server/adaptixserver | grep '^go[0-9]'
# Current server: go1.25.4 X:jsonv2,greenteagc

GOEXPERIMENT := jsonv2,greenteagc
DEPLOY_DIR   := ../../../Server/extenders/agent_nonameax
OUT          := $(DEPLOY_DIR)/agent_nonameax.so

.PHONY: all clean

all: $(OUT)

$(OUT): *.go ax_config.axs config.yaml
	GOEXPERIMENT=$(GOEXPERIMENT) go build -buildmode=plugin -o $(OUT) .
	cp ax_config.axs config.yaml $(DEPLOY_DIR)/
	@echo "  DEPLOY  $(OUT)"

clean:
	rm -f $(OUT)
