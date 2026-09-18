# Unit tests for the pure capability helpers.
#
# These require only the vendored SAI headers; no libsairedis, redis, or ASIC.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
CPPFLAGS := -I../include -I../include/sai -I../include/meta

TARGET := test_cap_logic
SRC    := test_cap_logic.cpp

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(SRC) ../include/cap_logic.h
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $(SRC)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
