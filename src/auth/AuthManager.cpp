#include "svf/auth/AuthManager.h"
#include "svf/auth/CryptoUtils.h"
#include <iostream>
#include <fstream>
#include <sstream>

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
        std::string salt = CryptoUtils::generateSalt();
        std::string hash = CryptoUtils::hashPassword("admin123", salt);
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
        if (CryptoUtils::verifyPassword(password, it->second.passwordHash, it->second.salt)) {
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
    
    std::string salt = CryptoUtils::generateSalt();
    std::string hash = CryptoUtils::hashPassword(password, salt);
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
