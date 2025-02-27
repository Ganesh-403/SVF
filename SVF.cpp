#include <iostream>
#include <algorithm>
#include <unordered_map>
#include <vector>
#include <memory>
#include <cstring>
#include <fstream>
#include <sstream>
#include <map>
#include <filesystem>
#include <openssl/sha.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include <chrono>

#define MAX_FILE_SIZE 4096
#define READ 1
#define WRITE 2
#define READ_WRITE 3
#define REGULAR 1
#define DIRECTORY 2

// Function to mask password input
#ifdef _WIN32
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
void disableEcho() {
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
}
void enableEcho() {
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    oldt.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
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


enum class UserRole {
    ADMIN,
    NORMAL_USER,
    READ_ONLY
};

std::string hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

class Inode {
public:
    std::string fileName;
    int inodeNumber;
    int fileSize = MAX_FILE_SIZE;
    int actualSize = 0;
    int fileType = REGULAR;
    int linkCount = 1;
    int referenceCount = 1;
    int permission;
    std::string owner;
    std::chrono::system_clock::time_point creationTime;
    std::chrono::system_clock::time_point modificationTime;
    std::vector<char> buffer;
    
    Inode(std::string name, int num, int perm, std::string ownerName, int type = REGULAR)
        : fileName(std::move(name)), inodeNumber(num), permission(perm), owner(ownerName), fileType(type) {
        creationTime = std::chrono::system_clock::now();
        modificationTime = creationTime;
        if (type == REGULAR) {
            buffer.resize(MAX_FILE_SIZE, 0);
        }
    }
};

class FileSystem {
private:
    std::unordered_map<std::string, std::shared_ptr<Inode>> fileTable;
    std::unordered_map<std::string, std::vector<std::string>> directories;
    int nextInode = 0;
    std::string currentUser;
    std::map<std::string, std::pair<std::string, UserRole>> users;
    std::string currentDirectory = "/";
    UserRole currentUserRole;
    std::map<std::string, int> openFiles;
    int nextFileDescriptor = 3; // 0, 1, 2 are reserved for stdin, stdout, stderr

    bool isPathValid(const std::string& path) {
        if (path.empty() || path[0] != '/') {
            return false;
        }
        
        // Check for valid characters and patterns
        if (path.find("..") != std::string::npos) {
            return true; // Allow parent directory traversal
        }
        
        for (char c : path) {
            if (!std::isalnum(c) && c != '/' && c != '_' && c != '.') {
                return false;
            }
        }
        
        return true;
    }

    std::string getAbsolutePath(const std::string& path) {
        if (path.empty()) return currentDirectory;
        
        if (path[0] == '/') return path;
        
        // Handle relative path
        std::string result = currentDirectory;
        if (result.back() != '/') result += '/';
        result += path;
        
        // Normalize the path (handle . and ..)
        std::vector<std::string> components;
        std::istringstream iss(result);
        std::string component;
        
        while (std::getline(iss, component, '/')) {
            if (component == "" || component == ".") continue;
            if (component == "..") {
                if (!components.empty()) components.pop_back();
            } else {
                components.push_back(component);
            }
        }
        
        result = "/";
        for (const auto& comp : components) {
            result += comp + "/";
        }
        
        // Remove trailing slash if not root
        if (result.length() > 1 && result.back() == '/') {
            result.pop_back();
        }
        
        return result;
    }

    void loadUsers() {
        std::ifstream file("users.txt");
        if (!file) {
            // Create default admin user if file doesn't exist
            std::ofstream newFile("users.txt");
            newFile << "admin " << hashPassword("admin123") << " ADMIN\n";
            newFile.close();
            users["admin"] = {hashPassword("admin123"), UserRole::ADMIN};
            std::cout << "Created default admin user. Username: admin, Password: admin123\n";
            return;
        }
        
        std::string line, username, password, role;
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            iss >> username >> password >> role;
            UserRole userRole = (role == "ADMIN") ? UserRole::ADMIN : 
                               (role == "NORMAL_USER") ? UserRole::NORMAL_USER : 
                               UserRole::READ_ONLY;
            users[username] = {password, userRole};
        }
    }

    void saveUsers() {
        std::ofstream file("users.txt");
        for (const auto& user : users) {
            std::string roleStr = (user.second.second == UserRole::ADMIN) ? "ADMIN" : 
                                 (user.second.second == UserRole::NORMAL_USER) ? "NORMAL_USER" : 
                                 "READ_ONLY";
            file << user.first << " " << user.second.first << " " << roleStr << "\n";
        }
    }

    bool hasPermission(const std::string& path, int reqPermission) {
        std::string absPath = getAbsolutePath(path);
        
        // Check if file exists
        if (fileTable.find(absPath) == fileTable.end()) {
            return false;
        }
        
        // Admins have all permissions
        if (currentUserRole == UserRole::ADMIN) {
            return true;
        }
        
        // Owner has all permissions
        if (fileTable[absPath]->owner == currentUser) {
            return (fileTable[absPath]->permission & reqPermission) == reqPermission;
        }
        
        // Read-only users can only read
        if (currentUserRole == UserRole::READ_ONLY) {
            return reqPermission == READ && (fileTable[absPath]->permission & READ);
        }
        
        // Normal users can read/write if permissions allow
        return (fileTable[absPath]->permission & reqPermission) == reqPermission;
    }

public:
    FileSystem() {
        loadUsers();
        
        // Initialize root directory if it doesn't exist
        if (directories.empty()) {
            directories["/"] = {};
            fileTable["/"] = std::make_shared<Inode>("/", nextInode++, READ_WRITE, "admin", DIRECTORY);
        }
    }
    
    ~FileSystem() {
        saveUsers();
    }

    bool login(const std::string& username, const std::string& password) {
        std::string hashedPassword = hashPassword(password);
        if (users.find(username) != users.end() && users[username].first == hashedPassword) {
            currentUser = username;
            currentUserRole = users[username].second;
            std::cout << "Login successful! Welcome " << username << " (Role: "
                      << ((currentUserRole == UserRole::ADMIN) ? "ADMIN" : 
                         (currentUserRole == UserRole::NORMAL_USER) ? "NORMAL_USER" : 
                         "READ_ONLY")
                      << ")\n";
            return true;
        }
        std::cerr << "Login failed! Invalid credentials.\n";
        return false;
    }

    void registerUser(const std::string& username, const std::string& password, UserRole role) {
        // Validate username
        if (username.empty() || username.length() < 3 || username.length() > 20) {
            std::cerr << "ERROR: Username must be between 3 and 20 characters.\n";
            return;
        }
        
        for (char c : username) {
            if (!std::isalnum(c) && c != '_') {
                std::cerr << "ERROR: Username can only contain alphanumeric characters and underscores.\n";
                return;
            }
        }
        
        // Validate password
        if (password.length() < 6) {
            std::cerr << "ERROR: Password must be at least 6 characters long.\n";
            return;
        }
        
        if (users.find(username) != users.end()) {
            std::cerr << "ERROR: User already exists.\n";
            return;
        }
        
        users[username] = {hashPassword(password), role};
        saveUsers();
        std::cout << "User registered successfully!\n";
    }
    
    void addUserFromAdmin() {
        if (currentUserRole != UserRole::ADMIN) {
            std::cerr << "ERROR: Only Admins can add new users.\n";
            return;
        }
        
        std::string newUsername, newPassword, roleInput;
        std::cout << "Enter new username: ";
        std::cin >> newUsername;
        std::cout << "Enter new password: ";
        std::cin.ignore();
        newPassword = getPasswordInput();
        
        std::cout << "Enter role (1:ADMIN, 2:NORMAL_USER, 3:READ_ONLY): ";
        int roleChoice;
        std::cin >> roleChoice;
        
        UserRole role;
        switch (roleChoice) {
            case 1: role = UserRole::ADMIN; break;
            case 2: role = UserRole::NORMAL_USER; break;
            case 3: role = UserRole::READ_ONLY; break;
            default: 
                std::cerr << "Invalid role choice. Defaulting to READ_ONLY.\n";
                role = UserRole::READ_ONLY;
        }
        
        registerUser(newUsername, newPassword, role);
    }
    
    void logout() {
        currentUser = "";
        currentDirectory = "/";
        std::cout << "Logged out successfully.\n";
    }
    
    void createFile(const std::string& filePath) {
        if (currentUser.empty()) {
            std::cerr << "ERROR: Must be logged in to create files.\n";
            return;
        }
        
        if (currentUserRole == UserRole::READ_ONLY) {
            std::cerr << "ERROR: Read-only users cannot create files.\n";
            return;
        }
        
        std::string absPath = getAbsolutePath(filePath);
        
        // Check if file already exists
        if (fileTable.find(absPath) != fileTable.end()) {
            std::cerr << "ERROR: File already exists.\n";
            return;
        }
        
        // Get directory path
        size_t lastSlash = absPath.find_last_of('/');
        if (lastSlash == std::string::npos) {
            std::cerr << "ERROR: Invalid file path.\n";
            return;
        }
        
        std::string dirPath = (lastSlash == 0) ? "/" : absPath.substr(0, lastSlash);
        std::string fileName = absPath.substr(lastSlash + 1);
        
        // Check if directory exists
        if (directories.find(dirPath) == directories.end()) {
            std::cerr << "ERROR: Directory does not exist.\n";
            return;
        }
        
        // Create inode for the file
        fileTable[absPath] = std::make_shared<Inode>(fileName, nextInode++, READ_WRITE, currentUser);
        directories[dirPath].push_back(fileName);
        
        std::cout << "File created: " << absPath << "\n";
    }
    
    void createDirectory(const std::string& dirPath) {
        if (currentUser.empty()) {
            std::cerr << "ERROR: Must be logged in to create directories.\n";
            return;
        }
        
        if (currentUserRole == UserRole::READ_ONLY) {
            std::cerr << "ERROR: Read-only users cannot create directories.\n";
            return;
        }
        
        std::string absPath = getAbsolutePath(dirPath);
        
        // Check if directory already exists
        if (directories.find(absPath) != directories.end()) {
            std::cerr << "ERROR: Directory already exists.\n";
            return;
        }
        
        // Get parent directory path
        size_t lastSlash = absPath.find_last_of('/');
        if (lastSlash == std::string::npos || lastSlash == absPath.length() - 1) {
            std::cerr << "ERROR: Invalid directory path.\n";
            return;
        }
        
        std::string parentPath = (lastSlash == 0) ? "/" : absPath.substr(0, lastSlash);
        std::string dirName = absPath.substr(lastSlash + 1);
        
        // Check if parent directory exists
        if (directories.find(parentPath) == directories.end()) {
            std::cerr << "ERROR: Parent directory does not exist.\n";
            return;
        }
        
        // Create inode for the directory
        directories[absPath] = {};
        fileTable[absPath] = std::make_shared<Inode>(dirName, nextInode++, READ_WRITE, currentUser, DIRECTORY);
        directories[parentPath].push_back(dirName);
        
        std::cout << "Directory created: " << absPath << "\n";
    }
    
    void changeDirectory(const std::string& dirPath) {
        std::string absPath = getAbsolutePath(dirPath);
        
        // Check if directory exists
        if (directories.find(absPath) == directories.end()) {
            std::cerr << "ERROR: Directory does not exist.\n";
            return;
        }
        
        currentDirectory = absPath;
        std::cout << "Current directory: " << currentDirectory << "\n";
    }
    
    void listDirectory(const std::string& dirPath = "") {
        std::string absPath = getAbsolutePath(dirPath);
        
        // Check if directory exists
        if (directories.find(absPath) == directories.end()) {
            std::cerr << "ERROR: Directory does not exist.\n";
            return;
        }
        
        std::cout << "Contents of " << absPath << ":\n";
        std::cout << "Name\t\tType\t\tSize\t\tOwner\t\tPermissions\n";
        std::cout << "---------------------------------------------------------\n";
        
        if (absPath != "/") {
            std::cout << "..\t\tDirectory\t-\t\t-\t\t-\n";
        }
        
        std::cout << ".\t\tDirectory\t-\t\t" 
                  << fileTable[absPath]->owner << "\t\t"
                  << ((fileTable[absPath]->permission & READ) ? "r" : "-")
                  << ((fileTable[absPath]->permission & WRITE) ? "w" : "-")
                  << "\n";
        
        for (const auto& item : directories[absPath]) {
            std::string itemPath = (absPath == "/") ? "/" + item : absPath + "/" + item;
            if (fileTable.find(itemPath) != fileTable.end()) {
                std::string type = (fileTable[itemPath]->fileType == DIRECTORY) ? "Directory" : "File";
                std::string size = (fileTable[itemPath]->fileType == DIRECTORY) ? "-" : 
                                  std::to_string(fileTable[itemPath]->actualSize) + "B";
                
                std::cout << item << "\t\t" << type << "\t\t" << size << "\t\t" 
                          << fileTable[itemPath]->owner << "\t\t"
                          << ((fileTable[itemPath]->permission & READ) ? "r" : "-")
                          << ((fileTable[itemPath]->permission & WRITE) ? "w" : "-")
                          << "\n";
            }
        }
    }
    
    int openFile(const std::string& filePath, int mode) {
        if (currentUser.empty()) {
            std::cerr << "ERROR: Must be logged in to open files.\n";
            return -1;
        }
        
        std::string absPath = getAbsolutePath(filePath);
        
        // Check if file exists
        if (fileTable.find(absPath) == fileTable.end()) {
            std::cerr << "ERROR: File does not exist.\n";
            return -1;
        }
        
        // Check if it's a directory
        if (fileTable[absPath]->fileType == DIRECTORY) {
            std::cerr << "ERROR: Cannot open a directory as a file.\n";
            return -1;
        }
        
        // Check permissions
        if (!hasPermission(absPath, mode)) {
            std::cerr << "ERROR: Insufficient permissions to open file in requested mode.\n";
            return -1;
        }
        
        // Create file descriptor
        int fd = nextFileDescriptor++;
        openFiles[absPath] = fd;
        
        std::cout << "File opened: " << absPath << " (FD: " << fd << ")\n";
        return fd;
    }
    
    bool writeFile(int fd, const std::string& content) {
        // Find the file path corresponding to the file descriptor
        std::string filePath;
        for (const auto& file : openFiles) {
            if (file.second == fd) {
                filePath = file.first;
                break;
            }
        }
        
        if (filePath.empty()) {
            std::cerr << "ERROR: Invalid file descriptor.\n";
            return false;
        }
        
        // Check write permission
        if (!hasPermission(filePath, WRITE)) {
            std::cerr << "ERROR: Insufficient permissions to write to file.\n";
            return false;
        }
        
        // Write content to file
        int contentSize = content.size();
        if (contentSize > MAX_FILE_SIZE) {
            std::cerr << "ERROR: Content exceeds maximum file size.\n";
            return false;
        }
        
        for (int i = 0; i < contentSize; i++) {
            fileTable[filePath]->buffer[i] = content[i];
        }
        
        fileTable[filePath]->actualSize = contentSize;
        fileTable[filePath]->modificationTime = std::chrono::system_clock::now();
        
        std::cout << "Wrote " << contentSize << " bytes to file.\n";
        return true;
    }
    
    std::string readFile(int fd) {
        // Find the file path corresponding to the file descriptor
        std::string filePath;
        for (const auto& file : openFiles) {
            if (file.second == fd) {
                filePath = file.first;
                break;
            }
        }
        
        if (filePath.empty()) {
            std::cerr << "ERROR: Invalid file descriptor.\n";
            return "";
        }
        
        // Check read permission
        if (!hasPermission(filePath, READ)) {
            std::cerr << "ERROR: Insufficient permissions to read from file.\n";
            return "";
        }
        
        // Read content from file
        int size = fileTable[filePath]->actualSize;
        std::string content(fileTable[filePath]->buffer.begin(), fileTable[filePath]->buffer.begin() + size);
        
        std::cout << "Read " << size << " bytes from file.\n";
        return content;
    }
    
    bool closeFile(int fd) {
        // Find the file path corresponding to the file descriptor
        std::string filePath;
        for (auto it = openFiles.begin(); it != openFiles.end(); ++it) {
            if (it->second == fd) {
                filePath = it->first;
                openFiles.erase(it);
                std::cout << "File closed: " << filePath << " (FD: " << fd << ")\n";
                return true;
            }
        }
        
        std::cerr << "ERROR: Invalid file descriptor.\n";
        return false;
    }
    
    bool deleteFile(const std::string& filePath) {
        if (currentUser.empty()) {
            std::cerr << "ERROR: Must be logged in to delete files.\n";
            return false;
        }
        
        if (currentUserRole == UserRole::READ_ONLY) {
            std::cerr << "ERROR: Read-only users cannot delete files.\n";
            return false;
        }
        
        std::string absPath = getAbsolutePath(filePath);
        
        // Check if file exists
        if (fileTable.find(absPath) == fileTable.end()) {
            std::cerr << "ERROR: File does not exist.\n";
            return false;
        }
        
        // Check if it's a directory
        if (fileTable[absPath]->fileType == DIRECTORY) {
            std::cerr << "ERROR: Cannot delete a directory with this command. Use rmdir instead.\n";
            return false;
        }
        
        // Check permissions
        if (currentUserRole != UserRole::ADMIN && fileTable[absPath]->owner != currentUser) {
            std::cerr << "ERROR: Only the owner or an admin can delete this file.\n";
            return false;
        }
        
        // Remove file from directory
        size_t lastSlash = absPath.find_last_of('/');
        if (lastSlash == std::string::npos) {
            std::cerr << "ERROR: Invalid file path.\n";
            return false;
        }
        
        std::string dirPath = (lastSlash == 0) ? "/" : absPath.substr(0, lastSlash);
        std::string fileName = absPath.substr(lastSlash + 1);
        
        auto& dirContents = directories[dirPath];
        auto it = std::find(dirContents.begin(), dirContents.end(), fileName);
        if (it != dirContents.end()) {
            dirContents.erase(it);
        }    
    
        // Close file if open
        for (auto it = openFiles.begin(); it != openFiles.end();) {
            if (it->first == absPath) {
                it = openFiles.erase(it);
            } else {
                ++it;
            }
        }
        
        // Remove file entry
        fileTable.erase(absPath);
        
        std::cout << "File deleted: " << absPath << "\n";
        return true;
    }
    
    bool removeDirectory(const std::string& dirPath) {
        if (currentUser.empty()) {
            std::cerr << "ERROR: Must be logged in to remove directories.\n";
            return false;
        }
        
        if (currentUserRole == UserRole::READ_ONLY) {
            std::cerr << "ERROR: Read-only users cannot remove directories.\n";
            return false;
        }
        
        std::string absPath = getAbsolutePath(dirPath);
        
        // Cannot remove root directory
        if (absPath == "/") {
            std::cerr << "ERROR: Cannot remove root directory.\n";
            return false;
        }
        
        // Check if directory exists
        if (directories.find(absPath) == directories.end()) {
            std::cerr << "ERROR: Directory does not exist.\n";
            return false;
        }
        
        // Check if directory is empty
        if (!directories[absPath].empty()) {
            std::cerr << "ERROR: Directory is not empty.\n";
            return false;
        }
        
        // Check permissions
        if (currentUserRole != UserRole::ADMIN && fileTable[absPath]->owner != currentUser) {
            std::cerr << "ERROR: Only the owner or an admin can remove this directory.\n";
            return false;
        }
        
        // Remove directory from parent
        size_t lastSlash = absPath.find_last_of('/');
        if (lastSlash == std::string::npos) {
            std::cerr << "ERROR: Invalid directory path.\n";
            return false;
        }
        
        std::string parentPath = (lastSlash == 0) ? "/" : absPath.substr(0, lastSlash);
        std::string dirName = absPath.substr(lastSlash + 1);
        
        auto& parentContents = directories[parentPath];
        auto it = std::find(parentContents.begin(), parentContents.end(), dirName);
        if (it != parentContents.end()) {
            parentContents.erase(it);
        }
        // Remove directory entry
        directories.erase(absPath);
        fileTable.erase(absPath);
        
        std::cout << "Directory removed: " << absPath << "\n";
        return true;
    }
    
    void showUserInfo() {
        if (currentUser.empty()) {
            std::cerr << "ERROR: Not logged in.\n";
            return;
        }
        
        std::cout << "User Information:\n";
        std::cout << "Username: " << currentUser << "\n";
        std::cout << "Role: " << 
            ((currentUserRole == UserRole::ADMIN) ? "ADMIN" : 
             (currentUserRole == UserRole::NORMAL_USER) ? "NORMAL_USER" : 
             "READ_ONLY") << "\n";
        std::cout << "Current Directory: " << currentDirectory << "\n";
        
        // Count user's files
        int fileCount = 0;
        int dirCount = 0;
        for (const auto& file : fileTable) {
            if (file.second->owner == currentUser) {
                if (file.second->fileType == DIRECTORY) {
                    dirCount++;
                } else {
                    fileCount++;
                }
            }
        }
        
        std::cout << "Owned Files: " << fileCount << "\n";
        std::cout << "Owned Directories: " << dirCount << "\n";
    }
    
    void showHelp() {
        std::cout << "\nFile System Commands:\n";
        std::cout << "--------------------\n";
        std::cout << "login <username> <password> - Log in to the system\n";
        std::cout << "register <username> <password> <role> - Register a new user\n";
        std::cout << "adduser - Add a new user (admin only)\n";
        std::cout << "logout - Log out of the system\n";
        std::cout << "touch <filename> - Create a new file\n";
        std::cout << "mkdir <dirname> - Create a new directory\n";
        std::cout << "cd <dirname> - Change current directory\n";
        std::cout << "ls [dirname] - List directory contents\n";
        std::cout << "open <filename> <mode> - Open a file (mode: 1=read, 2=write, 3=read-write)\n";
        std::cout << "write <fd> <content> - Write content to an open file\n";
        std::cout << "read <fd> - Read content from an open file\n";
        std::cout << "close <fd> - Close an open file\n";
        std::cout << "rm <filename> - Delete a file\n";
        std::cout << "rmdir <dirname> - Remove an empty directory\n";
        std::cout << "whoami - Show current user information\n";
        std::cout << "help - Show this help message\n";
        std::cout << "exit - Exit the program\n";
    }
};

int main() {
    FileSystem fs;
    std::string command;
    bool running = true;
    
    std::cout << "Simple File System (Type 'help' for commands)\n";
    
    while (running) {
        std::cout << "> ";
        std::cin >> command;
        
        if (command == "login") {
            std::string username, password;
            std::cin >> username;
            std::cout << "Password: ";
            std::cin.ignore();
            password = getPasswordInput();
            fs.login(username, password);
        } else if (command == "register") {
            std::string username, password, role;
            std::cin >> username;
            std::cout << "Password: ";
            std::cin.ignore();
            password = getPasswordInput();
            std::cout << "Role (1:ADMIN, 2:NORMAL_USER, 3:READ_ONLY): ";
            int roleChoice;
            std::cin >> roleChoice;
            
            UserRole userRole;
            switch (roleChoice) {
                case 1: userRole = UserRole::ADMIN; break;
                case 2: userRole = UserRole::NORMAL_USER; break;
                case 3: userRole = UserRole::READ_ONLY; break;
                default: 
                    std::cerr << "Invalid role choice. Defaulting to READ_ONLY.\n";
                    userRole = UserRole::READ_ONLY;
            }
            
            fs.registerUser(username, password, userRole);
        } else if (command == "adduser") {
            fs.addUserFromAdmin();
        } else if (command == "logout") {
            fs.logout();
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
                fs.listDirectory(dirname.substr(1)); // Remove the leading space
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
            std::cout << "Content: " << content << "\n";
        } else if (command == "close") {
            int fd;
            std::cin >> fd;
            fs.closeFile(fd);
        } else if (command == "rm") {
            std::string filename;
            std::cin >> filename;
            fs.deleteFile(filename);
        } else if (command == "rmdir") {
            std::string dirname;
            std::cin >> dirname;
            fs.removeDirectory(dirname);
        } else if (command == "whoami") {
            fs.showUserInfo();
        } else if (command == "help") {
            fs.showHelp();
        } else if (command == "exit") {
            running = false;
        } else {
            std::cerr << "ERROR: Unknown command. Type 'help' for a list of commands.\n";
        }
    }

    return 0;
}
