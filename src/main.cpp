#include "svf/auth/AuthManager.h"
#include "svf/vfs/FileSystem.h"
#include "svf/storage/VirtualDisk.h"
#include <iostream>
#include <string>

// Reusing the password masking utility from before
#ifdef _WIN32
#include <windows.h>
void disableEcho() {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
}
void enableEcho() {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode | ENABLE_ECHO_INPUT);
}
#else
#include <termios.h>
#include <unistd.h>
void disableEcho() {
    // Basic terminal suppression
}
void enableEcho() {
}
#endif

std::string getPasswordInput() {
    disableEcho();
    std::string password;
    std::getline(std::cin, password);
    enableEcho();
    std::cout << std::endl;
    return password;
}

void showHelp() {
    std::cout << "\nSecure File System V2 Commands:\n";
    std::cout << "--------------------\n";
    std::cout << "login <username> <password> - Log in to the system\n";
    std::cout << "register <username> <password> <role> - Register a new user\n";
    std::cout << "logout - Log out of the system\n";
    std::cout << "touch <filename> - Create a new file\n";
    std::cout << "mkdir <dirname> - Create a new directory\n";
    std::cout << "cd <dirname> - Change current directory\n";
    std::cout << "ls [dirname] - List directory contents\n";
    std::cout << "open <filename> <mode> - Open a file (mode: 1=read, 2=write, 3=read-write)\n";
    std::cout << "write <fd> <content> - Write content directly to Disk Blocks\n";
    std::cout << "read <fd> - Read content from Disk Blocks\n";
    std::cout << "close <fd> - Close an open file\n";
    std::cout << "exit - Exit the program and safely unmount disk\n";
}

int main() {
    std::cout << "Initializing Physical Disk Simulation...\n";
    VirtualDisk disk("svf_disk.img");
    if (!disk.mount()) {
        std::cerr << "Failed to mount the virtual disk. Exiting...\n";
        return 1;
    }

    AuthManager authManager;
    FileSystem fs(authManager, disk);
    
    std::string command;
    bool running = true;
    
    std::cout << "Secure File System V2 (Type 'help' for commands)\n";
    
    while (running) {
        std::cout << "> ";
        std::cin >> command;
        
        if (command == "login") {
            std::string username, password;
            std::cin >> username;
            std::cout << "Password: ";
            std::cin.ignore();
            password = getPasswordInput();
            authManager.login(username, password);
        } else if (command == "logout") {
            authManager.logout();
        } else if (command == "touch") {
            std::string filename;
            std::cin >> filename;
            fs.createFile(filename);
        } else if (command == "mkdir") {
            std::string dirname;
            std::cin >> dirname;
            fs.createDirectory(dirname);
        } else if (command == "cd") {
            std::string dirname;
            std::cin >> dirname;
            fs.changeDirectory(dirname);
        } else if (command == "ls") {
            std::string dirname;
            std::getline(std::cin, dirname);
            if (dirname.empty() || dirname == " ") {
                fs.listDirectory();
            } else {
                fs.listDirectory(dirname.substr(1));
            }
        } else if (command == "open") {
            std::string filename;
            int mode;
            std::cin >> filename >> mode;
            fs.openFile(filename, mode);
        } else if (command == "write") {
            int fd;
            std::string content;
            std::cin >> fd;
            std::cin.ignore();
            std::getline(std::cin, content);
            fs.writeFile(fd, content);
        } else if (command == "read") {
            int fd;
            std::cin >> fd;
            std::string content = fs.readFile(fd);
            if (!content.empty()) {
                std::cout << "Content: " << content << "\n";
            }
        } else if (command == "close") {
            int fd;
            std::cin >> fd;
            fs.closeFile(fd);
        } else if (command == "whoami") {
            fs.showUserInfo();
        } else if (command == "help") {
            showHelp();
        } else if (command == "exit") {
            running = false;
        } else {
            std::cerr << "ERROR: Unknown command. Type 'help' for a list of commands.\n";
        }
    }

    std::cout << "Unmounting Virtual Disk...\n";
    return 0;
}
