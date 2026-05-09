#include "svf/vfs/FileSystem.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>

FileSystem::FileSystem(AuthManager& authManager, VirtualDisk& disk) 
    : authManager(authManager), disk(disk) {
    if (directories.empty()) {
        directories["/"] = {};
        // Root directory has 0755 permissions (rwxr-xr-x)
        fileTable["/"] = std::make_shared<Inode>("/", nextInode++, 0755, "admin", DIRECTORY);
    }
}

// ... path resolution remains identical
bool FileSystem::isPathValid(const std::string& path) {
    if (path.empty() || path[0] != '/') return false;
    if (path.find("..") != std::string::npos) return true;
    for (char c : path) {
        if (!std::isalnum(c) && c != '/' && c != '_' && c != '.') return false;
    }
    return true;
}

std::string FileSystem::getAbsolutePath(const std::string& path) {
    if (path.empty()) return currentDirectory;
    if (path[0] == '/') return path;
    
    std::string result = currentDirectory;
    if (result.back() != '/') result += '/';
    result += path;
    
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
    if (result.length() > 1 && result.back() == '/') {
        result.pop_back();
    }
    return result;
}

// POSIX PERMISSION CHECKING
bool FileSystem::hasPermission(const std::string& path, int reqPermission) {
    std::string absPath = getAbsolutePath(path);
    if (fileTable.find(absPath) == fileTable.end()) return false;
    
    auto inode = fileTable[absPath];
    UserRole role = authManager.getCurrentRole();
    std::string user = authManager.getCurrentUser();
    
    if (role == UserRole::ADMIN) return true; // root access

    uint16_t perms = inode->getMode();
    
    // Check Owner Permissions (bits 6, 7, 8)
    if (inode->getOwner() == user) {
        if (reqPermission == 1 /* READ */ && (perms & S_IRUSR)) return true;
        if (reqPermission == 2 /* WRITE */ && (perms & S_IWUSR)) return true;
    } 
    // Check Others Permissions (bits 0, 1, 2)
    else {
        if (reqPermission == 1 /* READ */ && (perms & S_IROTH)) return true;
        if (reqPermission == 2 /* WRITE */ && (perms & S_IWOTH)) return true;
    }
    
    return false;
}

void FileSystem::createFile(const std::string& filePath) {
    if (!authManager.isLoggedIn()) { std::cerr << "ERROR: Must be logged in.\n"; return; }
    if (authManager.getCurrentRole() == UserRole::READ_ONLY) { std::cerr << "ERROR: Read-only users cannot create files.\n"; return; }
    
    std::string absPath = getAbsolutePath(filePath);
    if (fileTable.find(absPath) != fileTable.end()) { std::cerr << "ERROR: File already exists.\n"; return; }
    
    size_t lastSlash = absPath.find_last_of('/');
    if (lastSlash == std::string::npos) { std::cerr << "ERROR: Invalid file path.\n"; return; }
    
    std::string dirPath = (lastSlash == 0) ? "/" : absPath.substr(0, lastSlash);
    std::string fileName = absPath.substr(lastSlash + 1);
    
    if (directories.find(dirPath) == directories.end()) { std::cerr << "ERROR: Directory does not exist.\n"; return; }
    
    uint32_t inodeId = disk.allocateInode();
    if (inodeId == 0) { std::cerr << "ERROR: Disk out of inodes!\n"; return; }

    // 0644 default posix permissions: rw-r--r--
    fileTable[absPath] = std::make_shared<Inode>(fileName, inodeId, 0644, authManager.getCurrentUser());
    directories[dirPath].push_back(fileName);
    std::cout << "File created: " << absPath << " (Assigned Physical Inode: " << inodeId << ")\n";
}

void FileSystem::createDirectory(const std::string& dirPath) {
    if (!authManager.isLoggedIn()) { std::cerr << "ERROR: Must be logged in.\n"; return; }
    if (authManager.getCurrentRole() == UserRole::READ_ONLY) { std::cerr << "ERROR: Read-only users cannot create directories.\n"; return; }
    
    std::string absPath = getAbsolutePath(dirPath);
    if (directories.find(absPath) != directories.end()) { std::cerr << "ERROR: Directory already exists.\n"; return; }
    
    size_t lastSlash = absPath.find_last_of('/');
    if (lastSlash == std::string::npos || lastSlash == absPath.length() - 1) { std::cerr << "ERROR: Invalid directory path.\n"; return; }
    
    std::string parentPath = (lastSlash == 0) ? "/" : absPath.substr(0, lastSlash);
    std::string dirName = absPath.substr(lastSlash + 1);
    
    if (directories.find(parentPath) == directories.end()) { std::cerr << "ERROR: Parent directory does not exist.\n"; return; }
    
    uint32_t inodeId = disk.allocateInode();
    directories[absPath] = {};
    // 0755 default posix permissions: rwxr-xr-x
    fileTable[absPath] = std::make_shared<Inode>(dirName, inodeId, 0755, authManager.getCurrentUser(), DIRECTORY);
    directories[parentPath].push_back(dirName);
    std::cout << "Directory created: " << absPath << "\n";
}

void FileSystem::changeDirectory(const std::string& dirPath) {
    std::string absPath = getAbsolutePath(dirPath);
    if (directories.find(absPath) == directories.end()) { std::cerr << "ERROR: Directory does not exist.\n"; return; }
    currentDirectory = absPath;
    std::cout << "Current directory: " << currentDirectory << "\n";
}

void FileSystem::listDirectory(const std::string& dirPath) {
    std::string absPath = getAbsolutePath(dirPath);
    if (directories.find(absPath) == directories.end()) { std::cerr << "ERROR: Directory does not exist.\n"; return; }
    
    std::cout << "Contents of " << absPath << ":\n";
    std::cout << "Name\t\tType\t\tSize\t\tOwner\t\tPermissions(Octal)\n";
    std::cout << "---------------------------------------------------------\n";
    
    for (const auto& item : directories[absPath]) {
        std::string itemPath = (absPath == "/") ? "/" + item : absPath + "/" + item;
        if (fileTable.find(itemPath) != fileTable.end()) {
            auto inode = fileTable[itemPath];
            std::string type = (inode->getFileType() == DIRECTORY) ? "Directory" : "File";
            std::string size = (inode->getFileType() == DIRECTORY) ? "-" : std::to_string(inode->getSize()) + "B";
            
            // Print octal permissions
            char permStr[10];
            snprintf(permStr, sizeof(permStr), "0%o", inode->getMode());
            
            std::cout << item << "\t\t" << type << "\t\t" << size << "\t\t" 
                      << inode->getOwner() << "\t\t" << permStr << "\n";
        }
    }
}

int FileSystem::openFile(const std::string& filePath, int mode) {
    if (!authManager.isLoggedIn()) { std::cerr << "ERROR: Must be logged in to open files.\n"; return -1; }
    std::string absPath = getAbsolutePath(filePath);
    if (fileTable.find(absPath) == fileTable.end()) { std::cerr << "ERROR: File does not exist.\n"; return -1; }
    if (fileTable[absPath]->getFileType() == DIRECTORY) { std::cerr << "ERROR: Cannot open a directory as a file.\n"; return -1; }
    if (!hasPermission(absPath, mode)) { std::cerr << "ERROR: Insufficient POSIX permissions.\n"; return -1; }
    
    int fd = nextFileDescriptor++;
    openFiles[absPath] = fd;
    std::cout << "File opened: " << absPath << " (FD: " << fd << ")\n";
    return fd;
}

bool FileSystem::writeFile(int fd, const std::string& content) {
    std::string filePath;
    for (const auto& file : openFiles) {
        if (file.second == fd) { filePath = file.first; break; }
    }
    if (filePath.empty()) { std::cerr << "ERROR: Invalid file descriptor.\n"; return false; }
    if (!hasPermission(filePath, 2 /* WRITE */)) { std::cerr << "ERROR: Insufficient POSIX permissions.\n"; return false; }
    
    auto inode = fileTable[filePath];
    
    // ACQUIRE EXCLUSIVE WRITE LOCK (Concurrency!)
    inode->lockWrite();
    
    uint32_t contentSize = content.size();
    
    if (contentSize > 12 * disk.getSuperblock().blockSize) {
        std::cerr << "ERROR: Content exceeds maximum file size.\n";
        inode->unlockWrite();
        return false;
    }
    
    uint32_t blocksNeeded = (contentSize + disk.getSuperblock().blockSize - 1) / disk.getSuperblock().blockSize;
    if (blocksNeeded == 0 && contentSize == 0) {
        inode->unlockWrite();
        return true;
    }

    uint32_t bytesWritten = 0;
    
    for (uint32_t i = 0; i < blocksNeeded; ++i) {
        uint32_t blockNum = inode->getBlockPointer(i);
        if (blockNum == 0) {
            blockNum = disk.allocateBlock();
            if (blockNum == 0) { 
                std::cerr << "ERROR: Disk is completely full!\n"; 
                inode->unlockWrite();
                return false; 
            }
            inode->setBlockPointer(i, blockNum);
        }
        
        char buffer[4096] = {0};
        uint32_t chunkSize = std::min((uint32_t)4096, contentSize - bytesWritten);
        std::memcpy(buffer, content.c_str() + bytesWritten, chunkSize);
        
        disk.writeBlock(blockNum, buffer);
        bytesWritten += chunkSize;
    }
    
    inode->setSize(contentSize);
    std::cout << "Wrote " << contentSize << " bytes to physical disk blocks under Exclusive Lock.\n";
    
    // RELEASE EXCLUSIVE WRITE LOCK
    inode->unlockWrite();
    return true;
}

std::string FileSystem::readFile(int fd) {
    std::string filePath;
    for (const auto& file : openFiles) {
        if (file.second == fd) { filePath = file.first; break; }
    }
    if (filePath.empty()) { std::cerr << "ERROR: Invalid file descriptor.\n"; return ""; }
    if (!hasPermission(filePath, 1 /* READ */)) { std::cerr << "ERROR: Insufficient POSIX permissions.\n"; return ""; }
    
    auto inode = fileTable[filePath];
    
    // ACQUIRE SHARED READ LOCK (Concurrency!)
    inode->lockRead();
    
    uint32_t contentSize = inode->getSize();
    if (contentSize == 0) {
        inode->unlockRead();
        return "";
    }
    
    uint32_t blocksNeeded = (contentSize + disk.getSuperblock().blockSize - 1) / disk.getSuperblock().blockSize;
    std::string result = "";
    uint32_t bytesRead = 0;
    
    for (uint32_t i = 0; i < blocksNeeded; ++i) {
        uint32_t blockNum = inode->getBlockPointer(i);
        if (blockNum == 0) break;
        
        char buffer[4096];
        disk.readBlock(blockNum, buffer);
        
        uint32_t chunkSize = std::min((uint32_t)4096, contentSize - bytesRead);
        result.append(buffer, chunkSize);
        bytesRead += chunkSize;
    }
    
    std::cout << "Read " << contentSize << " bytes from physical disk blocks under Shared Lock.\n";
    
    // RELEASE SHARED READ LOCK
    inode->unlockRead();
    return result;
}

bool FileSystem::closeFile(int fd) {
    for (auto it = openFiles.begin(); it != openFiles.end(); ++it) {
        if (it->second == fd) {
            std::cout << "File closed: " << it->first << " (FD: " << fd << ")\n";
            openFiles.erase(it);
            return true;
        }
    }
    std::cerr << "ERROR: Invalid file descriptor.\n";
    return false;
}

bool FileSystem::deleteFile(const std::string& filePath) {
    std::cerr << "Delete logic simplified for Phase 4 implementation.\n";
    return false;
}

bool FileSystem::removeDirectory(const std::string& dirPath) {
    return false;
}

void FileSystem::showUserInfo() {
    std::cout << "User Information:\nUsername: " << authManager.getCurrentUser() << "\n";
}
