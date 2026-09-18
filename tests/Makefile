# Unit tests for the pure capability helpers and the JSON builder.
#
# These require only the vendored SAI headers; no libsairedis, redis, or ASIC.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
CPPFLAGS := -I../include -I../include/sai -I../include/meta

TARGETS := test_cap_logic test_json_value

.PHONY: all test clean

all: $(TARGETS)

test_cap_logic: test_cap_logic.cpp ../include/cap_logic.h
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $<

test_json_value: test_json_value.cpp ../include/json_value.h
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $<

test: $(TARGETS)
	./test_cap_logic
	./test_json_value

clean:
	rm -f $(TARGETS)
