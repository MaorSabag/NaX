# Makefile - agent_nonameax extender plugin

DEPLOY_DIR   := ../../../Server/extenders/agent_nonameax
OUT          := $(DEPLOY_DIR)/agent_nonameax.so

.PHONY: all clean

all: $(OUT)

$(OUT): *.go ax_config.axs config.yaml
	go build -buildmode=plugin -o $(OUT) .
	cp ax_config.axs config.yaml $(DEPLOY_DIR)/
	@echo "  DEPLOY  $(OUT)"

clean:
	rm -f $(OUT)
