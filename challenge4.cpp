/*
Detect single-character XOR

One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
*/

#include "challenges.h"
#include "encoding_utils.h"
#include "heuristic.h"

std::string challenge4() {
	//open and read
	//ittterate over every line
	//itterate over every char
	//score everything and return the best score

	std::ifstream file("4.txt");
	if (!file.is_open()) {
		return "File 4.txt failed to open";
	}

	std::string line;

	double bestScore = 0.0;
	int bestLine = 0, l = 0;
	std::string bestPlaintext = "";

	while (std::getline(file, line)) {
		std::string ciphertext = hexToText(line);

		for(unsigned char c = 0; c < 255; c++) {
			std::string key(ciphertext.length(), c);

			std::string plaintext = fixedXor(ciphertext, key);

			double score = scoreText(plaintext);

			if (score > bestScore) {
				bestScore = score;
				bestLine = l;
				bestPlaintext = plaintext;
			}
		}
		l++;
	}
	file.close();

	return bestPlaintext;
}