//
// Created by b on 5/27/20.
//

#include "color.h"
#include <stdio.h>
#include <stdlib.h>
#include <errors/errno.h>

#include "../aosh.h"

errval_t builtin_color(int argc, char ** argv) {
    for (int i = 0; i < 7; i++) {
        for (int j = 30; j < 38; j++) {
            for (int k = 40; k < 48; k++) {
                printf("\33[%d;%d;%dm AOS rocks! \33[m",
                       i, j, k);
            }
            printf("\n");
        }
    }
    printf("\033[0mNC (No color)\n");
    printf("\033[1;37mWHITE\t\033[0;30mBLACK\n");
    printf("\033[0;34mBLUE\t\033[1;34mLIGHT_BLUE\n");
    printf("\033[0;32mGREEN\t\033[1;32mLIGHT_GREEN\n");
    printf("\033[0;36mCYAN\t\033[1;36mLIGHT_CYAN\n");
    printf("\033[0;31mRED\t\033[1;31mLIGHT_RED\n");
    printf("\033[0;35mPURPLE\t\033[1;35mLIGHT_PURPLE\n");
    printf("\033[0;33mYELLOW\t\033[1;33mLIGHT_YELLOW\n");
    printf("\033[1;30mGRAY\t\033[0;37mLIGHT_GRAY\n");

    printf(COLOR_RESET);
    return SYS_ERR_OK;
}