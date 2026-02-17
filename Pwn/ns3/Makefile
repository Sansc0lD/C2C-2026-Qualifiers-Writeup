CC = g++
CFLAGS = -std=c++17 -Wall -Wextra -pthread -O2 -static-pie
SRC = src/main.cpp src/server.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = src/server

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJ) $(TARGET)
