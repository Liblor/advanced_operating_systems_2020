#include <stdio.h>

#include <aos/aos.h>

int main(int argc, char *argv[])
{
    char buf[] = "hello there";

    printf("%s", buf);

    return EXIT_SUCCESS;
}
