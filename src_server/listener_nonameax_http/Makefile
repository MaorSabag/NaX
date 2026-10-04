# Makefile - listener_nonameax_http extender plugin

DEPLOY_DIR   := ../../../Server/extenders/listener_nonameax_http
OUT          := $(DEPLOY_DIR)/listener_nonameax_http.so

.PHONY: all clean

all: $(OUT)

$(OUT): *.go
	go build -buildmode=plugin -o $(OUT) .
	@echo "  DEPLOY  $(OUT)"

clean:
	rm -f $(OUT)
