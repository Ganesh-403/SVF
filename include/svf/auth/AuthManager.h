#pragma once
#include <string>
#include <map>
#include <utility>

enum class UserRole {
    ADMIN,
    NORMAL_USER,
    READ_ONLY
};

class AuthManager {
private:
    // map username -> <hashed_password, salt, role>
    struct UserData {
        std::string passwordHash;
        std::string salt;
        UserRole role;
    };
    
    std::map<std::string, UserData> users;
    std::string currentUser;
    UserRole currentUserRole;
    std::string usersFilePath;

public:
    AuthManager(const std::string& filePath = "users.dat");
    ~AuthManager();

    void loadUsers();
    void saveUsers();

    bool login(const std::string& username, const std::string& password);
    void logout();
    bool registerUser(const std::string& username, const std::string& password, UserRole role);
    
    std::string getCurrentUser() const;
    UserRole getCurrentRole() const;
    bool isLoggedIn() const;
};
