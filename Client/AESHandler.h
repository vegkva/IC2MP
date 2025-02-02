#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <sodium.h>
#include "icmp.h"

// Forward declarations
class Client;


class AESHandler {
private:
    static AESHandler* instance;           // Singleton instance
    unsigned char aes_key[crypto_aead_aes256gcm_KEYBYTES];
    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    unsigned char aes_key_temp[crypto_aead_aes256gcm_KEYBYTES];
    unsigned char nonce_temp[crypto_aead_aes256gcm_NPUBBYTES];
    AESHandler();                          // Private constructor (singleton)

public:
    static AESHandler* getInstance();      // Singleton accessor
    void generateKeyAndNonce();            // Generate AES key and nonce
    void generateKeyAndNonceTemp();        // Generate AES key and nonce temporarily

    const unsigned char* getKey() const;   // Get AES key
    const unsigned char* getNonce() const; // Get Nonce

    std::vector<unsigned char> encryptMessage(const std::string& message);
    std::string decryptMessage(const std::vector<unsigned char>& ciphertext);

    std::string encryptKeyAndNonce();
    
    std::string encryptKeyAndNonceTemp();

    void Update();                         // Set key and nonce to the values from key_temp and nonce_temp

    void InitAES(SOCKET sockfd, Custom_icmp icmp, const std::string& ip_addr, bool connected);
};
