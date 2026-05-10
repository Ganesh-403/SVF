#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include "svf/vfs/Inode.h"
#include "svf/auth/AuthManager.h"
#include "svf/storage/VirtualDisk.h"

class FileSystem {
private:
    AuthManager& authManager;
    VirtualDisk& disk;
    std::string currentDirectory = "/";
    
    // Cache for performance
    std::map<std::string, std::shared_ptr<Inode>> fileTable;
    std::map<std::string, std::vector<std::string>> directories;
    std::map<int, std::shared_ptr<Inode>> openFileTable;
    
    int nextFd = 3; // Standard FDs reserved

    std::string getAbsolutePath(const std::string& path);
    bool isPathValid(const std::string& path);
    bool hasPermission(const std::string& path, int reqPermission);

public:
    FileSystem(AuthManager& authManager, VirtualDisk& disk);
    
    bool mount();
    bool unmount();

    void createFile(const std::string& filePath);
    void createDirectory(const std::string& dirPath);
    void changeDirectory(const std::string& dirPath);
    void listDirectory(const std::string& dirPath = "");
    
    void openFile(const std::string& filePath, int mode);
    void closeFile(int fd);
    void writeFile(int fd, const std::string& content);
    std::string readFile(int fd);
    
    void showUserInfo();
    void showDiskUsage();
    
    bool deleteFile(const std::string& filePath);
    bool removeDirectory(const std::string& dirPath);
};
