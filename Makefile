CC = gcc
CXX = g++
OBJS = main.cpp
TARGET = HTTPchange
LIBS = -ltins
HEADER = pk_change.h
CXXFLAGS=-g
.SUFFIXES : .cpp .o

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CXX) $(HEADER) $(OBJS) -o $(TARGET) $(LIBS)
#std = c++
#	$(CXX) $(OBJS) -o $(TARGET) $(LIBS) -std=c++11

clean:
	rm  -f $(TARGET)
