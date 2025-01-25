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

<br>

## Basic flow

- **Initial key exchange**
	- *Client generates AES key and nonce, encrypts these with server public key*
	- *Sends this to server, which decrypts and stores the AES key and nonce*
	- *Server responds with "INIT OK" -> key exchange successful*

<br>

- Client checks in with the server by sending "!ping"-command

- If server has a command for us:
	- Execute the command
	- Encrypt the result and split into blocks (by default blocks of size 32 bytes)
   		- Bigger size of blocks -> faster transmission of the result (but bad OPSEC)
	- Send result to server
    	- If server responds with "cancel" during the transmission of the result:
        	- Cancel the transmission
    	- Else:
        	- Continue with the transmission
- Else:
	- Do nothing (sleep for {timeout} seconds)

