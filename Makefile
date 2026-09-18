# Makefile for sai_cap_query
#
# Self-contained build: the SAI 1.17.5 headers are vendored under
# include/sai/ and the generated SAI metadata headers under include/meta/
# (produced by SAI 1.17.5 meta/parse.pl).
#
# Runtime libraries (libsairedis / libsaimeta / libsaimetadata / libswsscommon
# and their transitive dependencies) are expected in lib/. See
# build_in_mini.sh for how that directory is produced.
#
# Link notes:
#   -rpath,$ORIGIN/lib  + --disable-new-dtags:  resolve runtime libs from lib/,
#     using DT_RPATH (not RUNPATH) so it also applies to transitive deps
#     (libswsscommon, ...).
#   -rpath-link,lib:    resolve libsairedis' NEEDED chain at link time.
#   -lsaimeta -lsaimetadata: provide sai_serialize_*/saimeta::* used by
#     libsairedis but not declared as its Depends.
#
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
CPPFLAGS := -Iinclude -Iinclude/sai -Iinclude/meta -Iinclude/sairedis
LDFLAGS  := -Llib -Wl,-rpath,'$$ORIGIN/lib' -Wl,--disable-new-dtags -Wl,-rpath-link,lib
LIBS     := -lsairedis -lsaimeta -lsaimetadata

TARGET   := sai_cap_query
SRC      := sai_cap_query.cpp

.PHONY: all clean syntax-check check-sai-version test integration

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LIBS)

# Header-only validation; does not need the runtime libraries.
syntax-check: $(SRC)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -fsyntax-only $(SRC)

# Pure-logic unit tests; only needs the vendored headers.
test: check-sai-version
	$(MAKE) -C tests test

# End-to-end tests against a fake SAI adapter. META_DIR must point at a SAI
# checkout with generated metadata (see tests/Makefile.integration).
integration: check-sai-version
	$(MAKE) -C tests -f Makefile.integration integration

# The vendored headers and the generated metadata must agree on SAI 1.17.5.
check-sai-version:
	@maj=$$(sed -n 's/^#define SAI_MAJOR //p' include/sai/saiversion.h); \
	min=$$(sed -n 's/^#define SAI_MINOR //p' include/sai/saiversion.h); \
	rev=$$(sed -n 's/^#define SAI_REVISION //p' include/sai/saiversion.h); \
	ver="$$maj.$$min.$$rev"; \
	if [ "$$ver" != "1.17.5" ]; then \
		echo "ERROR: vendored SAI headers are $$ver, expected 1.17.5"; \
		exit 1; \
	fi; \
	echo "vendored SAI headers: $$ver"

clean:
	rm -f $(TARGET)
