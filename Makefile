CXX ?= g++
UNAME_S := $(shell uname -s)

BASE_CXXFLAGS := -std=c++20 -Wall -Wextra -Wpedantic -O2 -Isrc -idirafter third_party/include

ifeq ($(UNAME_S),Darwin)
  CXX := clang++
  HOMEBREW_PREFIX ?= /opt/homebrew
  PLATFORM_CXXFLAGS := -I$(HOMEBREW_PREFIX)/include \
    -I$(HOMEBREW_PREFIX)/opt/openssl/include \
    -I$(HOMEBREW_PREFIX)/opt/sqlite/include \
    -I$(HOMEBREW_PREFIX)/opt/mysql@8.0/include/mysql
  PLATFORM_LDFLAGS := -L$(HOMEBREW_PREFIX)/opt/openssl/lib \
    -L$(HOMEBREW_PREFIX)/opt/sqlite/lib \
    -L$(HOMEBREW_PREFIX)/opt/mysql@8.0/lib \
    -Wl,-rpath,$(HOMEBREW_PREFIX)/opt/mysql@8.0/lib \
    -lssl -lcrypto -lsqlite3 -lmysqlclient -lpthread
else
  MYSQL_CFLAGS := $(shell pkg-config --cflags mysqlclient 2>/dev/null || pkg-config --cflags mariadb 2>/dev/null || echo "-I/usr/include/mysql -I/usr/include/mariadb")
  MYSQL_LIBS := $(shell pkg-config --libs mysqlclient 2>/dev/null || pkg-config --libs mariadb 2>/dev/null || echo "-lmysqlclient")
  OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
  OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")
  SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
  SQLITE_LIBS := $(shell pkg-config --libs sqlite3 2>/dev/null || echo "-lsqlite3")
  PLATFORM_CXXFLAGS := $(MYSQL_CFLAGS) $(OPENSSL_CFLAGS) $(SQLITE_CFLAGS)
  PLATFORM_LDFLAGS := $(OPENSSL_LIBS) $(SQLITE_LIBS) $(MYSQL_LIBS) -lpthread
endif

CXXFLAGS := $(BASE_CXXFLAGS) $(PLATFORM_CXXFLAGS)
LDFLAGS := $(PLATFORM_LDFLAGS)

CORE_SRCS := src/config.cpp src/crypto.cpp src/database.cpp src/mysql_database.cpp src/auth_service.cpp src/http_server.cpp
CORE_OBJS := $(patsubst src/%.cpp,build/%.o,$(CORE_SRCS))
MAIN_OBJ := build/main.o
TEST_OBJ := build/test_auth.o

SERVER_BIN := bin/auth_server
TEST_BIN := bin/auth_tests

.PHONY: all build test run clean

all: $(SERVER_BIN)

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
