# Command and control over ICMP (Server)


![](./images/server.png)





## Todo
- Use SQLite to store data
- Implement stealthy response from server
  - The server should respond to client in blocks of 32 bytes
- Progress bar (feature)
  - Keep track of how many bytes the client has transmitted
  - Client executes the command, and in the first response to the server, client transmits the length of the result
    - Ex: Client executes "cat big.txt" -> Responds to server with total bytes of the encrypted text -> Starts transmission
  - Then server updates the progress bar (bytes received from client / total length of result)
  
## Bugs
- Plenty