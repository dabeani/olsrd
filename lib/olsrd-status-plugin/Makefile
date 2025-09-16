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

SRCS := src/olsrd_status_plugin.c src/httpd.c src/util.c src/connections.c rev/discover/ubnt_discover.c
HDRS := src/httpd.h src/util.h rev/discover/ubnt_discover.h

CFLAGS   ?= -O2
CFLAGS   += -fPIC
CPPFLAGS += -D_GNU_SOURCE -I$(OLSRD_INC) -I$(OLSRD_SRC) -Isrc -Irev/discover
WARNFLAGS?= -Wall -Wextra -Wformat=2 -Wshadow -Wpointer-arith -Wcast-align -Wstrict-prototypes -Wmissing-prototypes
LDFLAGS  += -shared
LDLIBS   += -lpthread

# Build type control: keep compatibility with run-script which passes -static
# BUILD_TYPE can be set explicitly, otherwise detect from incoming flags or toolchain.
BUILD_TYPE ?= auto

# If any incoming compile/link flags include -static, honor that and force static build.
ifneq (,$(filter -static,$(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)))
	BUILD_TYPE := static
endif

CC_BASENAME := $(notdir $(CC))
ifneq (,$(findstring musl,$(CC_BASENAME)))
$(info >>> musl cross-compilation detected)
# Default to shared for musl toolchains unless -static explicitly requested.
ifneq ($(BUILD_TYPE),static)
BUILD_TYPE := shared
$(info >>> BUILD_TYPE set to 'shared' for musl cross-compilation)
endif
endif

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

# Compute sanitized LDFLAGS/LDLIBS (remove any -static/-shared injected by toolchains)
LDFLAGS_SANITIZED := $(filter-out -static -shared,$(LDFLAGS))
LDLIBS_SANITIZED := $(filter-out -static -shared,$(LDLIBS))

# Sanitize CFLAGS for compilation: remove any -static and optionally -fPIC for static builds
CFLAGS_SANITIZED := $(filter-out -static,$(CFLAGS))
ifeq ($(BUILD_TYPE),static)
CFLAGS_COMPILE := $(filter-out -fPIC -static,$(CFLAGS))
else
CFLAGS_COMPILE := $(CFLAGS_SANITIZED)
endif

# Build object list under $(BUILDDIR)
OBJS := $(patsubst %.c,$(BUILDDIR)/%.o,$(SRCS))

# Plugin targets: shared .so or static archive .a
PLUGIN_STATIC := $(BUILDDIR)/lib$(PLUGIN_NAME).a
PLUGIN_SHARED := $(BUILDDIR)/$(SONAME)
ifeq ($(BUILD_TYPE),static)
PLUGIN_TARGET := $(PLUGIN_STATIC)
else
PLUGIN_TARGET := $(PLUGIN_SHARED)
endif

# Object compilation rule (creates parent dirs as needed)
$(BUILDDIR)/%.o: %.c $(HDRS) | $(BUILDDIR)
	$(MKDIR_P) $(dir $@)
	$(CC) $(CFLAGS_COMPILE) $(WARNFLAGS) $(CPPFLAGS) -c -o $@ $<

# Static archive target
$(PLUGIN_STATIC): $(OBJS) | $(BUILDDIR)
	ar rcs $@ $(OBJS)

# Shared object target
$(PLUGIN_SHARED): $(OBJS) | $(BUILDDIR)
	# Link shared plugin with sanitized LDFLAGS/LDLIBS
	$(CC) $(LDFLAGS_SANITIZED) -shared -o $@ $(OBJS) $(LDLIBS_SANITIZED)

$(BUILDDIR):
	$(MKDIR_P) $(BUILDDIR)

clean: status_plugin_clean
status_plugin_clean:
	$(RM) -r $(BUILDDIR)

status_plugin: $(PLUGIN_TARGET)

install: status_plugin_install
uninstall: status_plugin_uninstall

status_plugin_install: status_plugin
	@echo ">>> Installing plugin to $(DESTDIR)$(LIBDIR)"
	$(MKDIR_P) "$(DESTDIR)$(LIBDIR)"
	install -m 0755 "$(PLUGIN_TARGET)" "$(DESTDIR)$(LIBDIR)/"
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
	$(RM) "$(DESTDIR)$(LIBDIR)/$(notdir $(PLUGIN_TARGET))"
	$(RM) -r "$(DESTDIR)$(SHAREDIR)"
	@echo ">>> Done."
