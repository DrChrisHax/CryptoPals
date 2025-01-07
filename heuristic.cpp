#include "heuristic.h"
#include <iostream>

static const std::vector<double> freqEnglish = {
        8.167, // A
        1.492, // B
        2.782, // C
        4.253, // D
        12.702, // E
        2.228, // F
        2.015, // G
        6.094, // H
        6.966, // I
        0.153, // J
        0.772, // K
        4.025, // L
        2.406, // M
        6.749, // N
        7.507, // O
        1.929, // P
        0.095, // Q
        5.987, // R
        6.327, // S
        9.056, // T
        2.758, // U
        0.978, // V
        2.360, // W
        0.150, // X
        1.974, // Y
        0.074  // Z
};

double compareLetterFreq(const std::vector<double>& freqText) {
    double sumDiff = 0.0;
    for (size_t i = 0; i < 26; i++) {
        sumDiff += std::fabs(freqText[i] - freqEnglish[i]);
    }

    const double MAX_DIFF = 100.0;
    double distScore = 1.0 - (sumDiff / MAX_DIFF);

    if (distScore < 0.0) distScore = 0.0;
    if (distScore > 1.0) distScore = 1.0;

    return distScore;
}

double scoreText(const std::string& input) {
    if (input.empty()) { return 0.0; }


    //1. Frequency Scoring
    std::vector<int> letterCount(26, 0);
    int totalLetters = 0;
    for (unsigned char c : input) {
        if (std::isalpha(c)) {
            c = static_cast<unsigned char>(std::toupper(c));
            int index = c - 'A';
            if (index >= 0 && index < 26) {
                letterCount[index]++;
                totalLetters++;
            }
        }
    }

    std::vector<double> freqText(26, 0.0);
    if (totalLetters > 0) {
        for (int i = 0; i < 26; i++) {
            freqText[i] = (static_cast<double>(letterCount[i]) / totalLetters) * 100.0;
        }
    }
    double freqScore = 0.0;
    if (totalLetters > 0) {
        freqScore = compareLetterFreq(freqText);
    }

    //2. Count Printable Characters
    double printableChars = 0.0;
    for (unsigned char c : input) {
        if (std::isprint(c) || c == '\n' || c == '\t' || c == '\r') {
            printableChars++;
        }
    }
    double printableRatio = printableChars / input.size();

    //3. Count AlphaNum Characters
    double alphaNumChars = 0.0;
    for (unsigned char c : input) {
        if (std::isalnum(c) || c == ' ') {
            alphaNumChars++;
        }
    }
    double alphaNumRatio = alphaNumChars / input.size();

    return (freqScore + printableRatio + alphaNumRatio) / 3;
}