# olsrd-status-plugin — standalone Makefile (v10)
PLUGIN_NAME := olsrd_status
PLUGIN_VER  := 1.0
SONAME      := $(PLUGIN_NAME).so.$(PLUGIN_VER)
BUILDDIR    := build

OLSRD_TOP ?= ../..
OLSRD_INC ?= $(OLSRD_TOP)/include
OLSRD_SRC ?= $(OLSRD_TOP)/src

CC      ?= cc
RM      ?= rm -f
MKDIR_P ?= mkdir -p

SRCS := src/olsrd_status_plugin.c src/httpd.c src/util.c src/connections.c src/standalone_links_parser.c rev/discover/ubnt_discover.c
HDRS := src/httpd.h src/util.h rev/discover/ubnt_discover.h

CFLAGS   ?= -O2
CFLAGS   += -fPIC
CPPFLAGS += -D_GNU_SOURCE -I$(OLSRD_INC) -I$(OLSRD_SRC) -Isrc -Irev/discover
WARNFLAGS?= -Wall -Wextra -Wformat=2 -Wshadow -Wpointer-arith -Wcast-align -Wstrict-prototypes -Wmissing-prototypes
LDFLAGS  += -shared
LDLIBS   += -lpthread

# Do not use libcurl from system libraries; force building without libcurl
# so the plugin will use the external `curl` binary at runtime instead.
# This removes any dependency on libcurl headers/libs during build.
CURL_DETECTED := 0
$(info >>> libcurl support: DISABLED (building to use external 'curl' binary only))

# Control whether the plugin will spawn an external `curl` binary as a fallback
# Set ENABLE_CURL_FALLBACK=0 to disable the external-curl fallback and require
# either libcurl or no remote HTTPS fetching.
ENABLE_CURL_FALLBACK ?= 1
ifeq ($(ENABLE_CURL_FALLBACK),0)
CPPFLAGS += -DNO_CURL_FALLBACK=1
$(info >>> external curl fallback: DISABLED (set ENABLE_CURL_FALLBACK=1 to enable))
else
$(info >>> external curl fallback: ENABLED (set ENABLE_CURL_FALLBACK=0 to disable))
endif

# At build time we can optionally require that at least one fetch path is
# available (libcurl or curl binary). Set REQUIRE_FETCH=1 to make the build
# fail when neither is available.
REQUIRE_FETCH ?= 0
CURL_BIN_EXISTS := $(shell command -v curl >/dev/null 2>&1 && echo 1 || echo 0)
ifeq ($(REQUIRE_FETCH),1)
ifeq ($(CURL_DETECTED),0)
ifeq ($(CURL_BIN_EXISTS),0)
$(error >>> REQUIRE_FETCH=1: neither libcurl (dev) detected nor external 'curl' binary present; aborting build)
else
$(info >>> REQUIRE_FETCH=1: libcurl not detected but external curl binary found)
endif
else
$(info >>> REQUIRE_FETCH=1: libcurl detected; OK)
endif
endif

PREFIX   ?= /usr
LIBDIR   ?= $(PREFIX)/lib/olsrd
SHAREDIR ?= $(PREFIX)/share/olsrd-status-plugin
ASSETDIR ?= $(SHAREDIR)/www

SCRIPTS := scripts/fetch-assets.sh scripts/debug-plugin.sh

.PHONY: all clean status_plugin status_plugin_clean install uninstall status_plugin_install status_plugin_uninstall all_with_cli

# Optional CLI binary. Building the plugin alone is the default; use `make all_with_cli`
CLI_BIN := rev/discover/ubnt_discover_cli

.PHONY: ubnt_discover_cli

all: status_plugin

# Convenience target to build plugin + CLI
all_with_cli: status_plugin ubnt_discover_cli

ubnt_discover_cli: $(CLI_BIN)

$(CLI_BIN): rev/discover/ubnt_discover.c rev/discover/ubnt_discover_cli.c $(HDRS)
	$(CC) $(CFLAGS) $(WARNFLAGS) $(CPPFLAGS) -o $@ rev/discover/ubnt_discover.c rev/discover/ubnt_discover_cli.c $(LDLIBS)

$(BUILDDIR)/$(SONAME): $(SRCS) $(HDRS) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(WARNFLAGS) $(CPPFLAGS) -o $@ $(SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILDDIR):
	$(MKDIR_P) $(BUILDDIR)

clean: status_plugin_clean
status_plugin_clean:
	$(RM) -r $(BUILDDIR)

status_plugin: $(BUILDDIR)/$(SONAME)

install: status_plugin_install
uninstall: status_plugin_uninstall

status_plugin_install: status_plugin
	@echo ">>> Installing plugin to $(DESTDIR)$(LIBDIR)"
	$(MKDIR_P) "$(DESTDIR)$(LIBDIR)"
	install -m 0755 "$(BUILDDIR)/$(SONAME)" "$(DESTDIR)$(LIBDIR)/"
	@echo ">>> Installing shared data to $(DESTDIR)$(SHAREDIR)"
	$(MKDIR_P) "$(DESTDIR)$(ASSETDIR)"
	@if [ -d www ]; then \
	  echo ">>> Copying local www/ assets into $(DESTDIR)$(ASSETDIR)"; \
	  cp -a www/. "$(DESTDIR)$(ASSETDIR)/"; \
	else \
	  echo ">>> Note: no local www/ dir found; you can populate later with fetch-assets.sh"; \
	fi
	@for s in $(SCRIPTS); do \
	  if [ -f $$s ]; then \
	    echo ">>> Installing script $$s -> $(DESTDIR)$(SHAREDIR)"; \
	    install -m 0755 $$s "$(DESTDIR)$(SHAREDIR)/"; \
	  fi; \
	done
	@echo ">>> Done."

status_plugin_uninstall:
	@echo ">>> Removing plugin and data from $(DESTDIR)$(PREFIX)"
	$(RM) "$(DESTDIR)$(LIBDIR)/$(SONAME)"
	$(RM) -r "$(DESTDIR)$(SHAREDIR)"
	@echo ">>> Done."
