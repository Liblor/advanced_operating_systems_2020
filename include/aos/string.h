#ifndef BFOS_STRING_H
#define BFOS_STRING_H

#define CHAR_CODE_EOT (4)
#define CHAR_CODE_ASCII_NL (10)
#define CHAR_CODE_CR (13)

#define ENDL "\r\n"

#define COLOR_RED   "\x1B[31m"
#define COLOR_GRN   "\x1B[32m"
#define COLOR_YEL   "\x1B[33m"
#define COLOR_BLU   "\x1B[34m"
#define COLOR_MAG   "\x1B[35m"
#define COLOR_CYN   "\x1B[36m"
#define COLOR_WHT   "\x1B[37m"
#define COLOR_RESET "\x1B[0m"
#define CLR_SCREEN "\e[1;1H\e[2J"

#define IS_CHAR_LINEBREAK(c) (c == CHAR_CODE_CR || c == CHAR_CODE_ASCII_NL || c == CHAR_CODE_EOT)

#endif //BFOS_STRING_H
