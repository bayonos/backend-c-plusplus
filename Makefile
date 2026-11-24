CXX ?= clang++
CXXFLAGS := -std=c++20 -Wall -Wextra -Wpedantic -O2 \
	-I/opt/homebrew/include \
	-I/opt/homebrew/opt/openssl/include \
	-I/opt/homebrew/opt/sqlite/include \
	-I/opt/homebrew/opt/mysql@8.0/include/mysql \
	-Isrc
LDFLAGS := -L/opt/homebrew/opt/openssl/lib \
	-L/opt/homebrew/opt/sqlite/lib \
	-L/opt/homebrew/opt/mysql@8.0/lib \
	-Wl,-rpath,/opt/homebrew/opt/mysql@8.0/lib \
	-lssl -lcrypto -lsqlite3 -lmysqlclient -lpthread

CORE_SRCS := src/config.cpp src/crypto.cpp src/database.cpp src/mysql_database.cpp src/auth_service.cpp src/http_server.cpp
CORE_OBJS := $(patsubst src/%.cpp,build/%.o,$(CORE_SRCS))
MAIN_OBJ := build/main.o
TEST_OBJ := build/test_auth.o

SERVER_BIN := bin/auth_server
TEST_BIN := bin/auth_tests

.PHONY: all build test run clean

all: $(SERVER_BIN) $(TEST_BIN)

build:
	mkdir -p build bin

build/%.o: src/%.cpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/test_auth.o: tests/test_auth.cpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(SERVER_BIN): $(CORE_OBJS) $(MAIN_OBJ) | build
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_BIN): $(CORE_OBJS) $(TEST_OBJ) | build
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

test: $(TEST_BIN)
	./$(TEST_BIN)

run: $(SERVER_BIN)
	./$(SERVER_BIN)

clean:
	rm -rf build bin auth.db auth.db-shm auth.db-wal
