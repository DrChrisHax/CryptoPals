/*
Single-byte XOR cipher

The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
Achievement Unlocked

You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
*/
#include "challenges.h"
#include "encoding_utils.h"
#include "heuristic.h"

std::string challenge3() {
	const std::string hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

	std::string ciphertext = hexToText(hex);

	double bestScore = 0.0;
	unsigned char bestKey = 0;

	for (unsigned char c = 0; c < 255; c++) {
		std::string key(ciphertext.size(), c);

		std::string plaintext = fixedXor(ciphertext, key);

		double score = scoreText(plaintext);
		if (score > bestScore) {
			bestScore = score;
			bestKey = c;
		}
	}

	std::string key(ciphertext.size(), bestKey);

	return fixedXor(ciphertext, key);
}