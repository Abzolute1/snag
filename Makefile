PREFIX ?= /usr/local
DESTDIR ?=
BINARY = target/release/snag
COMPLETIONS_DIR = target/release/build/snag-*/out/completions

.PHONY: all build install uninstall clean completions

all: build

build:
	GENERATE_COMPLETIONS=1 cargo build --release

completions: build

install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/snag
	install -Dm644 man/snag.1 $(DESTDIR)$(PREFIX)/share/man/man1/snag.1
	@# Install shell completions if they were generated
	@for f in $(COMPLETIONS_DIR)/snag.bash; do \
		[ -f "$$f" ] && install -Dm644 "$$f" $(DESTDIR)$(PREFIX)/share/bash-completion/completions/snag || true; \
	done
	@for f in $(COMPLETIONS_DIR)/_snag; do \
		[ -f "$$f" ] && install -Dm644 "$$f" $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_snag || true; \
	done
	@for f in $(COMPLETIONS_DIR)/snag.fish; do \
		[ -f "$$f" ] && install -Dm644 "$$f" $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/snag.fish || true; \
	done

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/snag
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/snag.1
	rm -f $(DESTDIR)$(PREFIX)/share/bash-completion/completions/snag
	rm -f $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_snag
	rm -f $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/snag.fish

clean:
	cargo clean
