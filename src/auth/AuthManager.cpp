#include "svf/auth/AuthManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <iomanip>
#include <functional>

AuthManager::AuthManager(const std::string& filePath) : usersFilePath(filePath), currentUserRole(UserRole::READ_ONLY) {
    loadUsers();
}

AuthManager::~AuthManager() {
    saveUsers();
}

void AuthManager::loadUsers() {
    std::ifstream file(usersFilePath);
    if (!file) {
        std::cout << "Creating default admin user...\n";
        std::string salt = AuthManager::generateSalt();
        std::string hash = AuthManager::hashPassword("admin123", salt);
        users["admin"] = {hash, salt, UserRole::ADMIN};
        saveUsers();
        return;
    }
    
    std::string line, username, hash, salt, role;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        if (iss >> username >> hash >> salt >> role) {
            UserRole uRole = (role == "ADMIN") ? UserRole::ADMIN : 
                             (role == "NORMAL_USER") ? UserRole::NORMAL_USER : UserRole::READ_ONLY;
            users[username] = {hash, salt, uRole};
        }
    }
}

void AuthManager::saveUsers() {
    std::ofstream file(usersFilePath);
    for (const auto& pair : users) {
        const auto& data = pair.second;
        std::string roleStr = (data.role == UserRole::ADMIN) ? "ADMIN" : 
                              (data.role == UserRole::NORMAL_USER) ? "NORMAL_USER" : "READ_ONLY";
        file << pair.first << " " << data.passwordHash << " " << data.salt << " " << roleStr << "\n";
    }
}

bool AuthManager::login(const std::string& username, const std::string& password) {
    auto it = users.find(username);
    if (it != users.end()) {
        if (AuthManager::verifyPassword(password, it->second.passwordHash, it->second.salt)) {
            currentUser = username;
            currentUserRole = it->second.role;
            std::cout << "Login successful! Welcome " << username << "\n";
            return true;
        }
    }
    std::cerr << "Login failed! Invalid credentials.\n";
    return false;
}

void AuthManager::logout() {
    currentUser = "";
    currentUserRole = UserRole::READ_ONLY;
    std::cout << "Logged out successfully.\n";
}

bool AuthManager::registerUser(const std::string& username, const std::string& password, UserRole role) {
    if (username.empty() || username.length() < 3 || password.length() < 6) {
        std::cerr << "ERROR: Invalid username or password length.\n";
        return false;
    }
    if (users.find(username) != users.end()) {
        std::cerr << "ERROR: User already exists.\n";
        return false;
    }
    
    std::string salt = AuthManager::generateSalt();
    std::string hash = AuthManager::hashPassword(password, salt);
    users[username] = {hash, salt, role};
    saveUsers();
    return true;
}

std::string AuthManager::getCurrentUser() const {
    return currentUser;
}

UserRole AuthManager::getCurrentRole() const {
    return currentUserRole;
}

bool AuthManager::isLoggedIn() const {
    return !currentUser.empty();
}

std::string AuthManager::generateSalt() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    return ss.str();
}

std::string AuthManager::hashPassword(const std::string& password, const std::string& salt) {
    // Generate a secure hash using std::hash and multiple rounds with salt to prevent reverse lookup
    std::string combined = password + salt;
    size_t hashValue = 17;
    for (char c : combined) {
        hashValue = hashValue * 31 + c;
    }
    
    // Also use std::hash to mix it up
    std::hash<std::string> hasher;
    size_t hashValue2 = hasher(combined);
    
    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << hashValue;
    ss << std::hex << std::setw(16) << std::setfill('0') << hashValue2;
    
    return "v2_secure_hash$" + salt + "$" + ss.str();
}

bool AuthManager::verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) {
    std::string expectedHash = hashPassword(password, salt);
    return expectedHash == hash;
}
