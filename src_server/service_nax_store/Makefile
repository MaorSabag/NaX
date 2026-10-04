DEPLOY_DIR   := ../../../Server/extenders/service_nax_store
OUT          := $(DEPLOY_DIR)/nax_store.so

.PHONY: all clean deploy

all: $(OUT) deploy

$(OUT): *.go
	@mkdir -p $(DEPLOY_DIR)
	go build -buildmode=plugin -ldflags="-s -w" -o $(OUT) .
	@echo "  DEPLOY  $(OUT)"

deploy:
	@mkdir -p $(DEPLOY_DIR)
	@cp ax_config.axs config.yaml $(DEPLOY_DIR)/

clean:
	rm -f $(OUT)
