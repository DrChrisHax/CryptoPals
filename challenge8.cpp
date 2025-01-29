/*
Detect AES in ECB mode

In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
*/

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