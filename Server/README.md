# Command and control over ICMP (Server)


![](./images/server.png)





## Todo
- Implement stealthy response from server
  - The server should respond to client in blocks of 32 bytes
  
  
## Bugs
- When the server is restarting, some of the clients can't reconnect. Maybe related to the "INITIAL CONNECT"-part (client.print_info())