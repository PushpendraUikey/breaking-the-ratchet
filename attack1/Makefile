CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
TARGET   := attack1

$(TARGET): attack1.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: clean
