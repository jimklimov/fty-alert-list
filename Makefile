CXX=g++
CXXFLAGS=-Wall -pedantic -std=c++11
LDFLAGS=-llua -lcxxtools -lfty_common_logging


all: main

main:
	$(CXX) $(CXXFLAGS) $(LDFLAGS) asset.cpp rule.cpp lua_evaluate.cpp extended_rules.cpp main.cpp -E >preprocessed
	$(CXX) $(CXXFLAGS) $(LDFLAGS) asset.cpp rule.cpp lua_evaluate.cpp extended_rules.cpp main.cpp -o test

clean:
	rm -f test
