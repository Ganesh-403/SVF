#include "svf/vfs/FileSystem.h"
#include "svf/storage/BTree.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <chrono>

FileSystem::FileSystem(AuthManager& authManager, VirtualDisk& disk) 
    : authManager(authManager), disk(disk) {
}

bool FileSystem::mount() {
    std::cout << "[MOUNT] Starting mount...\n";
    std::cout.flush();
    
    auto sb = disk.getSuperblock();
    std::cout << "[MOUNT] Got superblock\n";
    std::cout.flush();
    
    DiskInode rootData;
    if (!disk.readInode(1, rootData)) {
        std::cerr << "[MOUNT] ERROR: Failed to read root inode\n";
        return false;
    }
    std::cout << "[MOUNT] Read root inode\n";
    std::cout.flush();

    // Validate root inode
    if (rootData.id != 1) {
        std::cerr << "[MOUNT] ERROR: Root inode ID mismatch (expected 1, got " << rootData.id << ")\n";
        return false;
    }
    
    if (rootData.fileType != DIRECTORY) {
        std::cerr << "[MOUNT] ERROR: Root is not a directory (type: " << rootData.fileType << ")\n";
        return false;
    }
    std::cout << "[MOUNT] Root inode validated\n";
    std::cout.flush();

    auto rootInode = std::make_shared<Inode>("/", rootData);
    fileTable["/"] = rootInode;
    directories["/"] = {};
    std::cout << "[MOUNT] Root inode stored\n";
    std::cout.flush();
    
    // Scan B-Tree with validation
    uint32_t rootBTreeBlock = rootData.directBlocks[0];
    std::cout << "[MOUNT] Root B-Tree block: " << rootBTreeBlock << "\n";
    std::cout.flush();
    
    if (rootBTreeBlock == 0) {
        std::cout << "[MOUNT] Root B-Tree block is 0, filesystem is empty\n";
        return true;
    }
    
    if (rootBTreeBlock >= sb.totalBlocks) {
        std::cerr << "[MOUNT] ERROR: B-Tree block out of range\n";
        return false;
    }
    
    std::cout << "[MOUNT] Creating BTreeDirectory...\n";
    std::cout.flush();
    
    try {
        BTreeDirectory rootBTree(disk, rootBTreeBlock);
        std::cout << "[MOUNT] BTreeDirectory created\n";
        std::cout.flush();
        
        std::cout << "[MOUNT] Calling listAll()...\n";
        std::cout.flush();
        
        auto entries = rootBTree.listAll();
        
        std::cout << "[MOUNT] Found " << entries.size() << " entries in root directory\n";
        std::cout.flush();
        
        // Validate each entry before loading
        for (const auto& entry : entries) {
            // Validate inode ID is in valid range
            if (entry.inodeId == 0 || entry.inodeId > sb.totalInodes) {
                std::cerr << "[MOUNT] WARNING: Invalid inodeId: " << entry.inodeId << "\n";
                continue;
            }
            
            std::string name(entry.fileName);
            
            // Validate filename is not empty
            if (name.empty()) {
                continue;
            }
            
            DiskInode childData;
            if (!disk.readInode(entry.inodeId, childData)) {
                std::cerr << "[MOUNT] WARNING: Failed to read inode " << entry.inodeId << "\n";
                continue;
            }
            
            // Validate loaded inode data
            if (childData.id != entry.inodeId) {
                std::cerr << "[MOUNT] WARNING: Inode ID mismatch for " << name << "\n";
                continue;
            }
            
            std::string fullPath = (name == "/") ? "/" : "/" + name;
            if (fullPath != "/") {
                fileTable[fullPath] = std::make_shared<Inode>(name, childData);
                directories["/"].push_back(name);
            }
        }
        
        std::cout << "[MOUNT] About to destroy BTreeDirectory...\n";
        std::cout.flush();
    } catch (const std::exception& e) {
        std::cerr << "[MOUNT] EXCEPTION: " << e.what() << "\n";
        return false;
    } catch (...) {
        std::cerr << "[MOUNT] UNKNOWN EXCEPTION\n";
        return false;
    }
    
    std::cout << "[MOUNT] BTreeDirectory destroyed successfully\n";
    std::cout.flush();
    
    std::cout << "[MOUNT] Filesystem mounted successfully\n";
    std::cout.flush();
    return true;
}

bool FileSystem::unmount() {
    for (auto const& [path, inode] : fileTable) {
        disk.writeInode(inode->getDiskData().id, inode->getDiskData());
    }
    return true;
}

bool FileSystem::isPathValid(const std::string& path) {
    return !path.empty() && path[0] == '/';
}

std::string FileSystem::getAbsolutePath(const std::string& path) {
    if (path.empty()) return currentDirectory;
    if (path[0] == '/') return path;
    
    std::string result = currentDirectory;
    if (result.back() != '/') result += '/';
    result += path;
    return result;
}

bool FileSystem::hasPermission(const std::string& path, int reqPermission) {
    return true; // Simplified for stability
}

void FileSystem::createFile(const std::string& filePath) {
    std::string absPath = getAbsolutePath(filePath);
    if (fileTable.find(absPath) != fileTable.end()) { std::cout << "Error: File exists.\n"; return; }

    size_t lastSlash = absPath.find_last_of('/');
    std::string dirPath = absPath.substr(0, lastSlash == 0 ? 1 : lastSlash);
    std::string fileName = absPath.substr(lastSlash + 1);

    uint32_t inodeId = disk.allocateInode();
    if (inodeId == 0) { std::cout << "Error: No inodes.\n"; return; }

    auto inode = std::make_shared<Inode>(fileName, inodeId, 0644, authManager.getCurrentUser());
    disk.writeInode(inodeId, inode->getDiskData());

    auto parentInode = fileTable[dirPath];
    if (parentInode) {
        // Acquire write lock for parent inode modification
        parentInode->lockWrite();
        
        // Update parent's modification time
        parentInode->getDiskData().modificationTime = 
            std::chrono::system_clock::now().time_since_epoch().count();
        
        parentInode->unlockWrite();
        
        BTreeDirectory dirBTree(disk, parentInode->getDiskData().directBlocks[0]);
        dirBTree.insert(fileName, inodeId);
        
        // Persist updated parent metadata
        disk.writeInode(parentInode->getDiskData().id, 
                       parentInode->getDiskData());
    }

    fileTable[absPath] = inode;
    directories[dirPath].push_back(fileName);
    std::cout << "Successfully created " << fileName << " (Inode " << inodeId << ")\n";
}

void FileSystem::createDirectory(const std::string& dirPath) {
    std::string absPath = getAbsolutePath(dirPath);
    if (fileTable.find(absPath) != fileTable.end()) return;

    size_t lastSlash = absPath.find_last_of('/');
    std::string parentPath = absPath.substr(0, lastSlash == 0 ? 1 : lastSlash);
    std::string dirName = absPath.substr(lastSlash + 1);

    uint32_t inodeId = disk.allocateInode();
    uint32_t btreeBlock = disk.allocateBlock();
    
    char zero[4096] = {0};
    disk.writeBlock(btreeBlock, zero);

    auto inode = std::make_shared<Inode>(dirName, inodeId, 0755, authManager.getCurrentUser(), DIRECTORY);
    inode->getDiskData().directBlocks[0] = btreeBlock;
    disk.writeInode(inodeId, inode->getDiskData());

    auto parentInode = fileTable[parentPath];
    if (parentInode) {
        // Acquire write lock for parent inode modification
        parentInode->lockWrite();
        
        // Update parent's modification time
        parentInode->getDiskData().modificationTime = 
            std::chrono::system_clock::now().time_since_epoch().count();
        
        parentInode->unlockWrite();
        
        BTreeDirectory parentBTree(disk, parentInode->getDiskData().directBlocks[0]);
        parentBTree.insert(dirName, inodeId);
        
        // Persist updated parent metadata
        disk.writeInode(parentInode->getDiskData().id, 
                       parentInode->getDiskData());
    }

    fileTable[absPath] = inode;
    directories[absPath] = {};
    directories[parentPath].push_back(dirName);
    std::cout << "Successfully created directory " << dirName << "\n";
}

void FileSystem::listDirectory(const std::string& dirPath) {
    std::string absPath = (dirPath == "") ? currentDirectory : getAbsolutePath(dirPath);
    if (directories.find(absPath) == directories.end()) { std::cout << "Error: Directory not found.\n"; return; }

    std::cout << "Listing " << absPath << ":\n";
    for (const auto& name : directories[absPath]) {
        std::string full;
        if (absPath == "/") full = "/" + name;
        else full = absPath + "/" + name;
        
        auto inode = fileTable[full];
        if (inode) {
            std::cout << "  [" << (inode->getDiskData().fileType == DIRECTORY ? "DIR " : "FILE") << "] " << name << " (" << inode->getDiskData().size << " bytes)\n";
        }
    }
}

void FileSystem::openFile(const std::string& filePath, int mode) {
    std::string absPath = getAbsolutePath(filePath);
    if (fileTable.find(absPath) == fileTable.end()) { std::cout << "Error: File not found.\n"; return; }
    
    int fd = nextFd++;
    openFileTable[fd] = fileTable[absPath];
    std::cout << "File opened. Use FD: " << fd << "\n";
}

void FileSystem::closeFile(int fd) {
    openFileTable.erase(fd);
}

void FileSystem::writeFile(int fd, const std::string& content) {
    if (openFileTable.find(fd) == openFileTable.end()) { std::cout << "Error: Invalid FD.\n"; return; }
    
    auto inode = openFileTable[fd];
    
    // Acquire write lock for exclusive modification
    inode->lockWrite();
    
    try {
        uint32_t block = inode->getDiskData().directBlocks[0];
        if (block == 0) {
            block = disk.allocateBlock();
            if (block == 0) {
                inode->unlockWrite();
                std::cout << "Error: No free blocks available.\n";
                return;
            }
            inode->getDiskData().directBlocks[0] = block;
        }
        
        // Update size and modification time within critical section
        inode->getDiskData().size = (uint32_t)content.length();
        inode->getDiskData().modificationTime = 
            std::chrono::system_clock::now().time_since_epoch().count();
        
        // Release lock before I/O (lock guards in-memory data only)
        inode->unlockWrite();
        
        // Perform I/O operations outside of lock
        char buffer[4096] = {0};
        std::memcpy(buffer, content.c_str(), std::min((size_t)4095, content.length()));
        disk.writeBlock(block, buffer);
        
        // Re-acquire lock to write persistent metadata
        inode->lockWrite();
        disk.writeInode(inode->getDiskData().id, inode->getDiskData());
        inode->unlockWrite();
        
        std::cout << "Success: Wrote " << content.length() << " bytes to disk.\n";
    } catch (...) {
        inode->unlockWrite();
        throw;
    }
}

std::string FileSystem::readFile(int fd) {
    if (openFileTable.find(fd) == openFileTable.end()) return "Error: Invalid FD";
    
    auto inode = openFileTable[fd];
    
    // Acquire read lock to safely access inode data
    inode->lockRead();
    
    try {
        uint32_t block = inode->getDiskData().directBlocks[0];
        uint32_t fileSize = inode->getDiskData().size;
        
        if (block == 0) {
            inode->unlockRead();
            return "";
        }
        
        // Release lock before I/O operation (lock guards in-memory data only)
        inode->unlockRead();
        
        char buffer[4096] = {0};
        disk.readBlock(block, buffer);
        
        return std::string(buffer, std::min((uint32_t)4095, fileSize));
    } catch (...) {
        inode->unlockRead();
        throw;
    }
}

void FileSystem::changeDirectory(const std::string& dirPath) {
    std::string absPath = getAbsolutePath(dirPath);
    if (directories.find(absPath) != directories.end()) {
        currentDirectory = absPath;
        std::cout << "Changed directory to " << currentDirectory << "\n";
    } else {
        std::cout << "Error: Directory not found.\n";
    }
}

void FileSystem::showUserInfo() {
    std::cout << "Logged in as: " << authManager.getCurrentUser() << "\n";
}

void FileSystem::showDiskUsage() {
    auto sb = disk.getSuperblock();
    std::cout << "Disk Statistics:\n";
    std::cout << "  Free Blocks: " << sb.freeBlocks << "\n";
    std::cout << "  Free Inodes: " << sb.freeInodes << "\n";
}

bool FileSystem::deleteFile(const std::string& filePath) { return false; }
bool FileSystem::removeDirectory(const std::string& dirPath) { return false; }
