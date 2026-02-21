# Makefile для macOS
CXX = clang++
CXXFLAGS = -O2 -Wall -std=c++11 -stdlib=libc++
LDFLAGS = -dynamiclib -install_name @rpath/libcrypto.dylib

TARGET = libcrypto.dylib
SOURCES = crypto.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^

%.o: %.cpp crypto.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install:
	cp $(TARGET) ..

.PHONY: all clean install