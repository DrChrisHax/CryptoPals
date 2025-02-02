/*
An ECB/CBC detection oracle

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
*/

#include "challenges.h"
#include "random.h"
#include "aes.h"
#include "encoding_utils.h"

static bool isCBC = false;

std::string encryptionOracle(const std::string& input) {
	std::string key = GenerateRandomBytes(16),
		ciphertext,
		plaintext = GenerateRandomBytes(5, 10) + input + GenerateRandomBytes(5, 10);

	if (RandomInt(0, 1) == 0) {
		ciphertext = aes_128_ecb_encrypt(plaintext, key);
		isCBC = false;
	}
	else {
		std::string iv = GenerateRandomBytes(16);
		ciphertext = aes_128_cbc_encrypt(plaintext, key, iv, 16);
		isCBC = true;
	}
	return ciphertext;
}


std::string challenge11() {
	std::string plaintext(64, 'A');

	for (int i = 0; i < 1024; i++) {
		std::string ciphertext = encryptionOracle(plaintext);
		if (hasRepeatingBlocks(ciphertext, 16) ^ isCBC) {
			continue;
		}
		else {
			return "FAIL";
		}
	}
	return "PASS";
}