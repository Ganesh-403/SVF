#include "svf/auth/AuthManager.h"
#include "svf/vfs/FileSystem.h"
#include "svf/storage/VirtualDisk.h"
#include <iostream>
#include <string>

void showHelp() {
    std::cout << "\n--- Available Commands ---\n";
    std::cout << "  register <user> <pass> <role_id> (role: 0=Admin, 1=User)\n";
    std::cout << "  login <user> <pass>\n";
    std::cout << "  ls, mkdir <name>, touch <name>\n";
    std::cout << "  open <name> 3, write <fd> <text>, read <fd>, close <fd>\n";
    std::cout << "  df, whoami, exit\n";
    std::cout << "--------------------------\n";
}

int main() {
    std::cout << "[SYSTEM] Starting Secure Virtual File System V2...\n";
    
    VirtualDisk disk("svf_disk.img");
    std::cout << "[DISK] Initializing binary storage...\n";
    if (!disk.mount()) {
        std::cerr << "[FATAL] Could not mount svf_disk.img. Check folder permissions.\n";
        return 1;
    }

    AuthManager authManager;
    FileSystem fs(authManager, disk);
    
    std::cout << "[VFS] Mounting internal structures...\n";
    std::cout.flush();
    
    bool mountSuccess = false;
    try {
        mountSuccess = fs.mount();
    } catch (const std::exception& e) {
        std::cerr << "[CRASH] Exception during mount: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[CRASH] Unknown exception during mount\n";
        return 1;
    }
    
    std::cout << "[VFS] Mount result: " << (mountSuccess ? "SUCCESS" : "FAILED") << "\n";
    std::cout.flush();
    
    if (!mountSuccess) {
        std::cerr << "[FATAL] File system structures are corrupt. Try deleting svf_disk.img.\n";
        return 1;
    }
    
    std::cout << "[READY] System is live. Type 'help' for commands.\n";
    std::cout.flush();  // Force flush output buffer
    
    std::string command;
    while (true) {
        std::cout << "\nsvf-shell> ";
        std::cout.flush();  // Ensure prompt is printed
        if (!(std::cin >> command)) {
            break;
        }
        
        if (command == "login") {
            std::string u, p;
            if (std::cin >> u >> p) {
                if (authManager.login(u, p)) {
                    std::cout << "Welcome back, " << u << "!\n";
                }
            }
        } else if (command == "register") {
            std::string u, p; int r;
            if (std::cin >> u >> p >> r) {
                if (authManager.registerUser(u, p, static_cast<UserRole>(r))) {
                    std::cout << "User '" << u << "' registered successfully.\n";
                }
            }
        } else if (command == "logout") {
            authManager.logout();
        } else if (command == "touch") {
            std::string f; std::cin >> f;
            fs.createFile(f);
        } else if (command == "mkdir") {
            std::string d; std::cin >> d;
            fs.createDirectory(d);
        } else if (command == "cd") {
            std::string d; std::cin >> d;
            fs.changeDirectory(d);
        } else if (command == "ls") {
            fs.listDirectory();
        } else if (command == "open") {
            std::string f; int m;
            std::cin >> f >> m;
            fs.openFile(f, m);
        } else if (command == "write") {
            int fd; std::string c;
            if (std::cin >> fd) {
                std::getline(std::cin >> std::ws, c);
                fs.writeFile(fd, c);
            }
        } else if (command == "read") {
            int fd; 
            if (std::cin >> fd) {
                std::string content = fs.readFile(fd);
                std::cout << "--- FILE CONTENT START ---\n";
                std::cout << content << "\n";
                std::cout << "--- FILE CONTENT END ---\n";
            }
        } else if (command == "close") {
            int fd; std::cin >> fd;
            fs.closeFile(fd);
            std::cout << "FD " << fd << " closed.\n";
        } else if (command == "df") {
            fs.showDiskUsage();
        } else if (command == "whoami") {
            fs.showUserInfo();
        } else if (command == "help") {
            showHelp();
        } else if (command == "exit") {
            break;
        } else {
            std::cout << "Unknown command: " << command << " (Type 'help')\n";
        }
    }

    std::cout << "[SYSTEM] Synchronizing metadata and shutting down...\n";
    fs.unmount();
    return 0;
}
