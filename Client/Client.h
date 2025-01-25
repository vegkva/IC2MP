#pragma once
#ifndef CLIENT_H
#define CLIENT_H
#include <string>

// Forward declarations
class AESHandler;

class Client {
public:
    static Client* instance;           // Singleton instance
    // Constructor to initialize client with default values
    Client();

    // Getters and setters for the class variables
    void setShell(const std::wstring& shell);
    std::wstring getShell() const;

    void setArguments(const std::string& arg);
    std::string getArguments() const;

    void setServerCommand(const std::string& srv_cmd);
    std::string getServerCommand() const;

    void setClientResponse(const std::string& client_rsp);
    std::string getClientResponse() const;

    static Client* getInstance();      // Singleton accessor
    AESHandler* getAesHandler() const; // Return pointer to AESHandler instance

    void setIP(const std::string& ip);
    std::string getIP() const;

    void setConnected(bool status);
    bool isConnected() const;

    void setCancelCmd(bool cancel_status);
    bool isCancelCmd() const;

    void setId(int clientId);
    int getId() const;

    void setSeq(int sequence);
    int getSeq() const;

    void setDelay(int delayTime);
    int getDelay() const;

    void setTimeout(int timeoutTime);
    int getTimeout() const;

    void setBlocksize(int blockSize);
    int getBlocksize() const;

    void cleanup();

    void FullCleanup();

private:
    AESHandler* aesHandler;
    std::wstring shell;
    std::string arguments;
    std::string server_command;
    std::string client_response;
    std::string ip_addr;
    bool cancel_cmd;
    bool connected;
    int id;
    int seq;
    int delay;
    int timeout;
    int blocksize;
};

#endif  // CLIENT_H
