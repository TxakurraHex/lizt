BIN_DIR  := /usr/bin
CONF_DIR := /etc/lizt
LOG_DIR  := /var/log/lizt
BINARY   := lizt_monitord

.PHONY: build install run clean

build:
	cargo build --release -p ebpf

# Run as: sudo make install
install:
	install -Dm755 target/release/$(BINARY) $(BIN_DIR)/$(BINARY)
	install -Dm644 conf/monitord_log4rs.yaml $(CONF_DIR)/monitord_log4rs.yaml
	install -Dm644 conf/lizt_monitord.service /etc/systemd/system/lizt_monitord.service
	mkdir -p $(LOG_DIR)
	systemctl daemon-reload
	@echo "Run: systemctl enable --now lizt_monitord"
	@[ -f $(CONF_DIR)/env ] || echo "WARNING: $(CONF_DIR)/env not found — create it with DATABASE_URL and NVD_API_KEY"
	
clean:
	cargo clean
