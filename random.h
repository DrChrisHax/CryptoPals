#pragma once

#include <string>
#include <cstdlib>
#include <ctime>

static bool seeded = false;

int RandomInt(int lowerBound, int upperBound);
std::string GenerateRandomBytes(int len);
std::string GenerateRandomBytes(int lowerBound, int upperBound);