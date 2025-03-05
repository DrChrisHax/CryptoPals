/*
The CBC padding oracle

This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.
What you're doing here.

This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.
*/
#include "challenges.h"
#include "aes.h"
#include "encoding_utils.h"
#include "random.h"

std::string KEY_C17 = GenerateRandomBytes(AES_BLOCKSIZE);

std::vector<std::string> messages = {
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
};

std::pair<std::string, std::string> encrypt() {
    int index = RandomInt(0, 9);

    std::string paddedData = padPKCS7(base64ToText(messages[index]), AES_BLOCKSIZE);
  
    std::string iv = GenerateRandomBytes(AES_BLOCKSIZE);
    std::string ciphertext = aes_128_cbc_encrypt(paddedData, KEY_C17, iv, AES_BLOCKSIZE);

    return std::make_pair(ciphertext, iv);
}

bool paddingOracle(const std::string& ciphertext) {
    try {
        // We do not care about the first block’s plaintext so we can pass a dummy IV.
        std::string dummyIV(AES_BLOCKSIZE, '\0');
        std::string decrypted = aes_128_cbc_decrypt(ciphertext, KEY_C17, dummyIV, AES_BLOCKSIZE);
        // unpadPKCS7 will throw if padding is invalid.
        std::string unpadded = unpadPKCS7WithErrors(decrypted);
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

// ----------------------------------------------------------------
// Decrypt a single block using the padding oracle attack.
// prevBlock is the block that comes immediately before the target ciphertext block.
std::string decryptBlock(const std::string& prevBlock, const std::string& currBlock) {
    if (prevBlock.size() != AES_BLOCKSIZE || currBlock.size() != AES_BLOCKSIZE)
        throw std::runtime_error("Block sizes not equal to AES block size.");

    std::vector<unsigned char> intermediate(AES_BLOCKSIZE, 0); // holds I = D(currBlock)
    std::string decryptedBlock(AES_BLOCKSIZE, '\0');           // will hold the recovered plaintext block

    // Work from rightmost byte (index 15) to left (index 0)
    for (int pos = AES_BLOCKSIZE - 1; pos >= 0; pos--) {
        // padVal is the value we want to see (1 for last byte, 2 for second-last, etc.)
        unsigned char padVal = static_cast<unsigned char>(AES_BLOCKSIZE - pos);

        // For each guess 0..255:
        for (int guess = 0; guess < 256; guess++) {
            // Create a modified copy of prevBlock which we will alter.
            std::string modifiedBlock = prevBlock;  // note: each char is one byte

            // For positions after 'pos', set them so that when decrypted they yield padVal.
            for (int j = pos + 1; j < AES_BLOCKSIZE; j++) {
                // modifiedBlock[j] = originalByte XOR intermediate[j] XOR padVal
                modifiedBlock[j] = prevBlock[j] ^ intermediate[j] ^ padVal;
            }
            // Now modify the current position using our guess.
            modifiedBlock[pos] = prevBlock[pos] ^ static_cast<unsigned char>(guess) ^ padVal;

            // Construct the two-block ciphertext: modifiedBlock || currBlock.
            std::string attackCipher = modifiedBlock + currBlock;

            // Query the padding oracle.
            if (paddingOracle(attackCipher)) {
                // We have a candidate.
                // (Note: There is a rare possibility of a false positive when the real padding byte equals padVal;
                // you can add an extra check if desired.)
                intermediate[pos] = static_cast<unsigned char>(guess) ^ padVal;
                // Recover plaintext: P = I XOR original prevBlock byte.
                decryptedBlock[pos] = intermediate[pos] ^ prevBlock[pos];
                break;
            }
        }
    }
    return decryptedBlock;
}


std::string challenge17() {
    std::pair<std::string, std::string> result = encrypt();
    std::string ciphertext = result.first;
    std::string iv = result.second;

    // Prepend the IV to the ciphertext so that block[0] = IV, block[1] = first ciphertext block, etc.
    std::string fullCipher = iv + ciphertext;
    std::vector<std::string> blocks = splitBlocks(fullCipher, AES_BLOCKSIZE);
    if (blocks.size() < 2)
        throw std::runtime_error("Not enough blocks.");

    std::string recoveredPlaintext;
    // For each block pair (prev, current), starting with (IV, C1), (C1, C2), etc.
    for (size_t i = 1; i < blocks.size(); i++) {
        std::string plainBlock = decryptBlock(blocks[i - 1], blocks[i]);
        recoveredPlaintext += plainBlock;
    }
    // Remove the PKCS#7 padding from the recovered plaintext.
    return unpadPKCS7(recoveredPlaintext);
}
