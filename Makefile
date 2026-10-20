# Plain Makefile build for Linux/macOS (GCC or Clang); CMake is the primary build
# and the only one used on Windows.
#   make            # bin/bl-device bin/bl-client bin/bl-bench bin/unit_tests
#   make test
#   make CXX=clang++
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion
LDLIBS   += -pthread

SRC  := $(wildcard src/*.cpp)
OBJ  := $(SRC:src/%.cpp=obj/%.o)
APPS := bin/bl-device bin/bl-client bin/bl-bench bin/unit_tests

all: $(APPS)

obj/%.o: src/%.cpp src/*.hpp | obj
	$(CXX) $(CXXFLAGS) -c $< -o $@

bin/bl-%: apps/bl_%.cpp apps/cli.hpp $(OBJ) | bin
	$(CXX) $(CXXFLAGS) $< $(OBJ) -o $@ $(LDLIBS)

bin/unit_tests: tests/unit_tests.cpp $(OBJ) | bin
	$(CXX) $(CXXFLAGS) $< $(OBJ) -o $@ $(LDLIBS)

obj bin:
	mkdir -p $@

test: bin/unit_tests
	./bin/unit_tests

clean:
	rm -rf obj bin

.PHONY: all test clean
