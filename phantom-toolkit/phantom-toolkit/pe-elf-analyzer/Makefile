CXX     = g++
CXXFLAGS= -std=c++17 -Wall -Wextra -O2 -Iinclude
TARGET  = phantom-analyzer
SRCS    = src/main.cpp src/pe_parser.cpp src/elf_parser.cpp \
          src/entropy.cpp src/string_extractor.cpp src/report.cpp

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: clean
