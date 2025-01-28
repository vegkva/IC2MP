# Command and control over ICMP (client)

*Does not need adminstrator privileges to run*

First make necessary changes in [main.cpp](./main.cpp) and [AESHandler.cpp](./AESHandler.cpp) 

## Compile on Windows
- Import project into Visual Studio 2022
- Install libsodium (for cryptography) (https://doc.libsodium.org/installation)
	- Preferably to `C:\libraries\libsodium`, or else you have to change this in the configurations
- If you use static library:
	- Configuration Properties -> C/C++ -> Preprocessor -> Preprocessor Definitions = SODIUM_STATIC

<br>

## Compile on linux
*This will create a binary twice as big as a binary compiled with Visual Studio*

```sh
apt update
apt install mingw-w64
```

```sh
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-stable-mingw.tar.gz
tar -xzf libsodium-1.0.20-stable-mingw.tar.gz -C /opt libsodium-win64/
```

```sh
make
```
