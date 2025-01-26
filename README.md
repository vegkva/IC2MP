# Disclaimer

This project is intended for educational purposes and authorized security assessments only. The use of this tool must comply with all applicable laws and regulations.

### By using this tool, you agree to the following:

- You will only use it with proper authorization: This tool is designed to help security professionals identify and address vulnerabilities in systems they own or have explicit, written permission to assess.

- You accept full responsibility for your actions: The developers and contributors of this project will not be held liable for any misuse, damages, or legal consequences arising from the use or distribution of this software.

- You will comply with all applicable laws: Unauthorized use of this tool may violate laws and regulations in your jurisdiction. Ensure that you fully understand the legal implications before using this tool.



## What is this

A "covert channel" Command and Control framework.
This framework uses the data portion of an ICMP-packet to transmit encrypted data between the server and connected clients.

![](./images/wireshark.png)


## Basic flow of the C2


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
