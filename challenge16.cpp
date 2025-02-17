/*

CBC bitflipping attacks

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="

.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

    Completely scrambles the block the error occurs in
    Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.

Before you implement this attack, answer this question: why does CBC mode have this property?

*/
#include "challenges.h"
#include "encoding_utils.h"
#include "aes.h"
#include "random.h"
#include "print_utils.h"

const std::string KEY_C16 = GenerateRandomBytes(AES_BLOCKSIZE);
const std::string IV_C16 = GenerateRandomBytes(AES_BLOCKSIZE);

std::string sanitize(const std::string& input) {
    std::string output;
    for (char c : input) {
        if (c == ';' || c == '=') {
            output += '%' + textToHex(std::string(1, c));
        }
        else {
            output += c;
        }
    }
    return output;
}

std::string encrypt(const std::string& plaintext) {
    const std::string prefix = "comment1=cooking%20MCs;userdata=";
    const std::string suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    std::string sanitized = sanitize(plaintext);

    return aes_128_cbc_encrypt(prefix + sanitized + suffix, KEY_C16, IV_C16, AES_BLOCKSIZE);
}

bool isAdmin(const std::string& ciphertext) {
    const std::string target = ";admin=true;";
    std::string decrypted = aes_128_cbc_decrypt(ciphertext, KEY_C16, IV_C16, AES_BLOCKSIZE);
    return decrypted.find(target) != std::string::npos;
}

std::string bitFlipAttack() {
    const int prefixLength = 32;

    std::string target = ";admin=true;";
    std::string craftedInput(target.size() + AES_BLOCKSIZE, 'A');

    std::string encrypted = encrypt(craftedInput);

    for (int i = 0; i < target.size(); i++) {
        encrypted[prefixLength + i] ^= ('A' ^ target[i]);
    }

    return encrypted;
}

std::string challenge16() {
    std::string naive = "; admin = true;";

    std::string naiveEncrypt = encrypt(naive);
    std::string result = "\nNormal Encryption: " + textToHex(naiveEncrypt) + "\n";
    result += "Is admin = ";
    result += (isAdmin(naiveEncrypt)) ? "True" : "False";

    result += "\nDecrypted naive text: " + formatAsPrintable(aes_128_cbc_decrypt(naiveEncrypt, KEY_C16, IV_C16, AES_BLOCKSIZE)) + "\n";

    std::string bitFlipEncrypt = bitFlipAttack();
    result += "\nBit Flip Encryption: " + textToHex(bitFlipEncrypt) + "\n";
    result += "Is admin = ";
    result += (isAdmin(bitFlipEncrypt)) ? "True" : "False";

    result += "\nDecrypted attack text: " + formatAsPrintable(aes_128_cbc_decrypt(bitFlipEncrypt, KEY_C16, IV_C16, AES_BLOCKSIZE)) + "\n";

    return result;
}
