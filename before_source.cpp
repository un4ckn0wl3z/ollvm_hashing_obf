#include <iostream>
#include <string>

int main() {
    std::string password;

    std::cout << "Enter the password" << std::endl;
    std::cin >> password;

    if (password == "6uncr4ck6") {
        std::cout << "Good Job!" << std::endl;
    } else {
        std::cout << "Denied!" << std::endl;
    }

    return 0;
}
