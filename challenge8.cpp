

#include "challenges.h"
#include "encoding_utils.h"
#include "aes.h"

std::string challenge8() {
    std::ifstream file("8.txt");
    if (!file.is_open()) {
        return "File 8.txt failed to open";
    }

    std::string line;
    std::vector<std::string> matches;

    while (std::getline(file, line)) {
        if (hasRepeatingBlocks(hexToText(line), 16)) {
            matches.push_back(line);
        }
    }
    file.close();

    switch (matches.size()) {
    case 0 :
        return "No ECB encoded ciphertext found.";
    case 1:
        return matches.at(0);
    default:
        return "Multiple ECB encoded ciphertexts found.";
    }
}