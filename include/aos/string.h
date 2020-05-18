#ifndef BFOS_STRING_H
#define BFOS_STRING_H

#define CHAR_CODE_EOT (4)
#define CHAR_CODE_ASCII_NL (10)
#define CHAR_CODE_CR (13)

#define ENDL "\r\n"

#define IS_CHAR_LINEBREAK(c) (c == CHAR_CODE_CR || c == CHAR_CODE_ASCII_NL || c == CHAR_CODE_EOT)

#endif //BFOS_STRING_H
