/*
Byte-at-a-time ECB decryption (Harder)

Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.
Stop and think for a second.

What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
*/
#include "challenges.h"
#include "aes.h"
#include "encoding_utils.h"
#include "random.h"
#include <unordered_map>

const std::string KEY_C14 = GenerateRandomBytes(16);
const std::string RANDOM_PREFIX = GenerateRandomBytes(8, 64);

std::string blackBoxEncryptionWithPrefix(const std::string& input) {
    const std::string flag = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    const std::string plaintext = RANDOM_PREFIX + input + base64ToText(flag);
    return aes_128_ecb_encrypt(plaintext, KEY_C14);
}

int detectPrefixLength(int blockSize) {
    for (int i = blockSize * 2; i < blockSize * 3; i++) {
        std::string input(i, 'A');
        std::string ciphertext = blackBoxEncryptionWithPrefix(input);

        int totalNumBlocks = ciphertext.length() / blockSize;
        for (int blockIndex = 0; blockIndex < totalNumBlocks - 1; blockIndex++) {
            std::string blockA = ciphertext.substr(blockIndex * blockSize, blockSize);
            std::string blockB = ciphertext.substr((blockIndex + 1) * blockSize, blockSize);

            if (blockA.compare(blockB) == 0) {
                int prefixLen = blockIndex * blockSize - (i - (2 * blockSize));

                return prefixLen;
            }
        }
    }
    throw std::runtime_error("Failed to find prefix length.");
}

std::string discoverTargetWithPrefix(int blockSize, int prefixLength) {
    std::string target;

    int prefixPad = (blockSize - (prefixLength % blockSize)) % blockSize;
    int startBlock = (prefixLength + prefixPad) / blockSize;
    int totalLength = blackBoxEncryptionWithPrefix(std::string(prefixLength, 'A')).length();
    int targetLength = totalLength - (prefixLength + prefixPad);

    for (int i = 0; i < targetLength; i++) {
        std::string craftedInput(prefixPad, 'A');
        craftedInput += std::string(blockSize - 1 - (i % blockSize), 'A');

        int blockIndex = startBlock + (i / blockSize);

        std::string targetBlock = blackBoxEncryptionWithPrefix(craftedInput).substr(blockIndex * blockSize, blockSize);

        std::unordered_map<std::string, char> blockDictionary;
        for (int j = 0; j < 256; j++) {
            std::string testInput = craftedInput + target + static_cast<char>(j);
            std::string testBlock = blackBoxEncryptionWithPrefix(testInput).substr(blockIndex * blockSize, blockSize);
            blockDictionary[testBlock] = static_cast<char>(j);
        }

        if (blockDictionary.find(targetBlock) != blockDictionary.end()) {
            target += blockDictionary[targetBlock];
        }
    }

    return target;
}

std::string challenge14() {
    int blockSize = findECBBlockSize(blackBoxEncryptionWithPrefix);
    std::string target = "";

    if (isECBMode(blockSize, blackBoxEncryptionWithPrefix)) {
        int prefixLength = detectPrefixLength(blockSize);
        target = discoverTargetWithPrefix(blockSize, prefixLength);
    }
    else {
        throw std::runtime_error("ECB mode not detected.");
    }
    return target;
}