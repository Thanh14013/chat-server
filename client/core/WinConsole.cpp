#include "WinConsole.h"
#include <iostream>

#ifdef _WIN32
#include <conio.h>

bool nonblocking_getline(std::string& input) {
    if (_kbhit()) {
        int c = _getch();
        if (c == '\r' || c == '\n') {
            std::cout << std::endl;
            return true;
        } else if (c == '\b' || c == 127) { // backspace
            if (!input.empty()) {
                input.pop_back();
                std::cout << "\b \b" << std::flush;
            }
        } else if (c == 224 || c == 0) {
            // arrow keys / special keys, ignore the next char
            _getch();
        } else if (c >= 32 && c <= 126) {
            input.push_back((char)c);
            std::cout << (char)c << std::flush;
        }
    }
    return false;
}
#endif
