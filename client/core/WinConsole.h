#pragma once
#include <string>

#ifdef _WIN32
bool nonblocking_getline(std::string& input);
#endif
