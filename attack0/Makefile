CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
TARGET   := attack0

$(TARGET): attack0.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: clean
