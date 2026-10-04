# Makefile - listener_nonameax_smb extender plugin

DEPLOY_DIR   := ../../../Server/extenders/listener_nonameax_smb
OUT          := $(DEPLOY_DIR)/listener_nonameax_smb.so

.PHONY: all clean

all: $(OUT)

$(OUT): *.go
	@mkdir -p $(DEPLOY_DIR)
	go build -buildmode=plugin -o $(OUT) .
	@cp config.yaml ax_config.axs $(DEPLOY_DIR)/
	@echo "  DEPLOY  $(OUT)"

clean:
	rm -f $(OUT)
