# Unit tests for the pure capability helpers, the JSON builder, and the
# ZMQ endpoint facts the transport preflight decides on.
#
# These require only the vendored SAI headers; no libsairedis, redis, or ASIC.
# test_zmq_endpoint additionally creates real UNIX sockets under /tmp (with
# test-only names) to tell a live endpoint from a leftover socket file.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
CPPFLAGS := -I../include -I../include/sai -I../include/meta

TARGETS := test_cap_logic test_json_value test_zmq_endpoint

.PHONY: all test clean

all: $(TARGETS)

test_cap_logic: test_cap_logic.cpp ../include/cap_logic.h
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $<

test_json_value: test_json_value.cpp ../include/json_value.h
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $<

test_zmq_endpoint: test_zmq_endpoint.cpp ../include/zmq_endpoint.h
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $<

test: $(TARGETS)
	./test_cap_logic
	./test_json_value
	./test_zmq_endpoint

clean:
	rm -f $(TARGETS)
