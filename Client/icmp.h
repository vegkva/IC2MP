#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>

// Link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#pragma pack(push, 1)
struct icmp_packet_t {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
};
#pragma pack(pop)

struct iphdr {
	unsigned char version_ihl;
	unsigned char tos;
	unsigned short tot_len;
	unsigned short id;
	unsigned short frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short check;
	unsigned int saddr;
	unsigned int daddr;
};


class Custom_icmp {



public:
	Custom_icmp(int id, int seq, float delay);
	int getId();
	int getSeq();
	float getDelay();
	void setId(int id);
	void setSeq(int seq);
	void setDelay(float new_delay);
	SOCKET createSocket();
	icmp_packet_t* createPacket(std::string& payload, std::string& last_element, bool connected);
	std::string sendPing(SOCKET sockfd, const std::string& ip_addr, std::vector<std::string>& payload, bool connected, bool exit = false);
	std::string receivePing(SOCKET sockfd);
	unsigned short calculateChecksum(void* b, int len);




private:
	int p_id;
	int p_seq;
	float p_delay;
};