/*
Break repeating-key XOR
It is officially on, now.

This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

    Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

    this is a test

    and

    wokka wokka!!!

    is 37. Make sure your code agrees before you proceed.
    For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    Solve each block as if it was single-character XOR. You already have code to do this.
    For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
No, that's not a mistake.

We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.

*/

#include "challenges.h"
#include "encoding_utils.h"
#include "heuristic.h"

std::vector<int> findKeySize(const std::string& data) {
    std::vector<std::pair<double, int>> distances;
    distances.reserve(38);

    for (size_t keySize = 2; keySize < 40; keySize++) {

        if (keySize * 4 > data.length()) break;
        

        double totalDistance = 0.0;
        for (int i = 0; i < 3; i++) {
            std::string block1(data.begin() + keySize * i, data.begin() + keySize * (i + 1));
            std::string block2(data.begin() + keySize * (i + 1), data.begin() + keySize * (i + 2));

            totalDistance += hammingDistance(block1, block2) / static_cast<double>(keySize);
        }
        
        double avgDistance = totalDistance / 3.0;

        distances.push_back(std::make_pair(avgDistance, keySize));
    }

    std::vector<int> bestKeySizes;
    std::sort(distances.begin(), distances.end());

    bestKeySizes.push_back(distances[0].second);
    bestKeySizes.push_back(distances[1].second);
    bestKeySizes.push_back(distances[2].second);

    return bestKeySizes;
}

std::string findKey(int keySize, const std::string& data) {

    std::vector<std::string> blocks(keySize);
    std::string key(keySize, '\0');

    for (size_t i = 0; i < data.length(); i++) {
        blocks[i % keySize].push_back(data[i]);
    }

    for (size_t i = 0; i < keySize; i++) {
        double bestScore = -1.0;
        unsigned char bestKeyChar = '\0';

        for (unsigned char c = 0; c < 255; c++) {
            std::string decrypt(blocks[i].size(), '\0');
            for (size_t k = 0; k < blocks[i].length(); k++) {
                decrypt[k] = blocks[i][k] ^ c;
            }

            double score = scoreText(decrypt);

            if (score > bestScore) {
                bestScore = score;
                bestKeyChar = c;
            }
        }
        key[i] = bestKeyChar;   
    }
    return key;
}

std::string challenge6() {

    std::ifstream file("6.txt");
    if (!file.is_open()) {
        return "File 6.txt failed to open";
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();

    std::string data = base64ToText(buffer.str());

    std::vector<int> keySizes = findKeySize(data);

    std::string bestDecryptedMessage;
    double bestScore = -1.0;
    std::string bestKey;

    for (int size : keySizes) {
        std::string key = findKey(size, data);
        std::string decrypted = repeatingXor(data, key);

        double score = scoreText(decrypted);
        if (score > bestScore) {
            bestScore = score;
            bestDecryptedMessage = decrypted;
            bestKey = key;
        }
    }

    return  bestDecryptedMessage + "\nKey:" + bestKey;
}