/*
Byte-at-a-time ECB decryption (Simple)

Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.

Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

    Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
    Detect that the function is using ECB. You already know, but do this step anyways.
    Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
    Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
    Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
    Repeat for the next byte.

Congratulations.

This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can decrypt the contents of those ciphertexts, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.
*/

#include "challenges.h"
#include "aes.h"
#include "encoding_utils.h"
#include "random.h"
#include <unordered_map>

const static std::string KEY_C12 = GenerateRandomBytes(16);

std::string blackBoxEncryption(const std::string& input) {
    const std::string flag = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    const std::string plaintext = input + base64ToText(flag);
    return aes_128_ecb_encrypt(plaintext, KEY_C12);
}

std::string discoverTarget(int blockSize) {
    std::string target;
    int targetLen = blackBoxEncryption("").length();

    for (int i = 0; i < targetLen; i++) {
        std::string craftedInput(blockSize - 1 - (i % blockSize), 'A');
        std::string targetBlock = blackBoxEncryption(craftedInput).substr((i / blockSize) * blockSize, blockSize);

        std::unordered_map<std::string, char> blockDictionary;
        for (int j = 0; j < 256; j++) {
            std::string testInput = craftedInput + target + static_cast<char>(j);
            std::string testBlock = blackBoxEncryption(testInput).substr((i / blockSize) * blockSize, blockSize);
            blockDictionary[testBlock] = static_cast<char>(j);
        }

        if (blockDictionary.find(targetBlock) != blockDictionary.end()) {
            target += blockDictionary[targetBlock];
        }
    }

    return target;
}

std::string challenge12() {
    int blockSize = findECBBlockSize(blackBoxEncryption);
    std::string target = "";

    if (isECBMode(blockSize, blackBoxEncryption)) {
        target = discoverTarget(blockSize);
    }
    else {
        throw std::runtime_error("ECB mode not detected.");
        return target;
    }

    return target;
}


