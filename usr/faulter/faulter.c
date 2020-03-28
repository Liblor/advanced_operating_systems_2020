#include <stdio.h>

#include <aos/aos.h>

int main(int argc, char *argv[])
{
    printf("Faulter spawned\n");

    const char *addr = (char *) VADDR_OFFSET - BASE_PAGE_SIZE;

    printf("Byte at address %p is '%x'\n", addr, *addr);

    return EXIT_SUCCESS;
}
