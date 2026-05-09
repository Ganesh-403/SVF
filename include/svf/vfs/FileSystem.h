#pragma once
#include "svf/vfs/Inode.h"
#include "svf/auth/AuthManager.h"
#include "svf/storage/VirtualDisk.h"
#include <unordered_map>
#include <map>
#include <vector>
#include <memory>
#include <string>

class FileSystem {
private:
    std::unordered_map<std::string, std::shared_ptr<Inode>> fileTable;
    std::unordered_map<std::string, std::vector<std::string>> directories;
    int nextInode = 0;
    std::string currentDirectory = "/";
    std::map<std::string, int> openFiles;
    int nextFileDescriptor = 3;

    AuthManager& authManager;
    VirtualDisk& disk;

    bool isPathValid(const std::string& path);
    std::string getAbsolutePath(const std::string& path);
    bool hasPermission(const std::string& path, int reqPermission);

public:
    FileSystem(AuthManager& authManager, VirtualDisk& disk);
    ~FileSystem() = default;

    void createFile(const std::string& filePath);
    void createDirectory(const std::string& dirPath);
    void changeDirectory(const std::string& dirPath);
    void listDirectory(const std::string& dirPath = "");
    
    int openFile(const std::string& filePath, int mode);
    bool writeFile(int fd, const std::string& content);
    std::string readFile(int fd);
    bool closeFile(int fd);
    
    bool deleteFile(const std::string& filePath);
    bool removeDirectory(const std::string& dirPath);
    void showUserInfo();
};
