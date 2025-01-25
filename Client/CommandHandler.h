#pragma once
#ifndef COMMAND_HANDLER_H
#define COMMAND_HANDLER_H
#include "Client.h"// Include the Client header to use Client class
#include "icmp.h"
#include <string>
#include <vector>


class CommandHandler {
public:
    // Constructor that initializes the timeout value
    CommandHandler(Client& client);


    // Function to handle the server result (command and value)
    void handleServerCommand(int sockfd, Custom_icmp icmp, const std::string& ip_addr, bool connected);

private:
    Client& client;  // Reference to the Client object

    // Helper to set the delay value
    std::string setDelay(const std::string& delayValue);

    // Helper to set the timeout value
    std::string setTimeout(const std::string& timeoutValue);

    // Helper to set the timeout value
    std::string setBlocksize(const std::string& blocksizeValue);
};

#endif  // COMMAND_HANDLER_H
