# Command and control over ICMP (client)



## Compile on linux
- Requirements: 
	- MinGW-w64
		```
		apt update
		apt install mingw-w64
		```
	- libsodium (https://download.libsodium.org/libsodium/releases/)
		- Extract to `/opt/`

- Run `make`

## Compile on Windows
- Import project into Visual Studio 2022
- Install libsodium (for cryptography) (https://doc.libsodium.org/installation)
- If you use static library:
	- Configuration Properties -> C/C++ -> Preprocessor -> Preprocessor Definitions = SODIUM_STATIC

