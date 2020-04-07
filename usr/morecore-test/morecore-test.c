
#include <stdio.h>

#include <aos/aos.h>

#define NUM_SIZE 103
static size_t SIZES[NUM_SIZE] = {21, 23, 4242, 1128, 2312321, 1, 3298, 4903, 9933, 1311, 3904, 7140, 8522,
        5417, 7398, 4409, 8619, 3356, 8369, 2982, 2243, 5901, 9203, 425, 4441, 166, 4422, 2919,
        1894, 6099, 799, 3416, 8145, 3365, 1702, 7739, 161, 491, 5402, 8150, 5988, 3895, 5416, 5928,
        4419, 480, 909, 5674, 192, 7634, 1669, 2714, 638, 1849, 5719, 9689, 3503, 1710, 8041, 3646,
        336, 6237, 5587, 3855, 7196, 1840, 2006, 4866, 2310, 4427, 2668, 5477, 8380, 702, 2138,
        2519, 4898, 1294, 8540, 3886, 79, 2923, 4416, 9006, 6736, 8490, 1933, 6417, 7084, 4858,
        3755, 8347, 5878, 7216, 9029, 262, 2261, 658, 9641, 8499};

__unused
static void lazy_malloc(void) {
    debug_printf("start lazy_malloc\n");
    debug_printf("malloc 256MiB\n");
    char *buf = malloc(1 << 26);

    debug_printf("write at different locations\n");
    buf[0] = 'A';
    buf[1337] = 'A';
    buf[0x1000000] = 'A';
    buf[0x3000000] = 'A';
    buf[0x395550B] = 'A';
    free(buf);
    debug_printf("end lazy_malloc\n");
}

__unused
static void malloc_free(void) {
    debug_printf("start malloc_free\n");
    char *buf[NUM_SIZE];

    for (int i = 0; i < NUM_SIZE; i++) {
        buf[i] = malloc(SIZES[i]);
        memset(buf[i], 'A', SIZES[i]);
        free(buf[i]);
    }
    debug_printf("end malloc_free\n");
}

__unused
static void malloc_then_free(void) {
    debug_printf("start malloc_then_free\n");
    char *buf[NUM_SIZE];

    for (int i = 0; i < NUM_SIZE; i++) {
        buf[i] = malloc(SIZES[i]);
        memset(buf[i], 'A', SIZES[i]);
    }

    for (int i = 0; i < NUM_SIZE; i++) {
        free(buf[i]);
    }
    debug_printf("end malloc_then_free\n");
}

__unused
static void m_f_m_f(void) {
    debug_printf("start m_f_m_f\n");
    char *buf[NUM_SIZE];

    for (int i = 0; i < NUM_SIZE; i++) {
        buf[i] = malloc(SIZES[i]);
        memset(buf[i], 'A', SIZES[i]);
    }

    for (int i = 0; i < NUM_SIZE; i++) {
        free(buf[i]);
    }

    for (int i = NUM_SIZE-1; i >= 0; i--) {
        buf[i] = malloc(SIZES[i]);
        memset(buf[i], 'B', SIZES[i]);
    }

    for (int i = 0; i < NUM_SIZE; i++) {
        free(buf[i]);
    }

    debug_printf("end m_f_m_f\n");
}

__unused
static void exp_malloc(void) {
    debug_printf("start exp_malloc\n");
    const size_t num = 10;
    char *buf[num];

    for (int i = 1; i < num; i++) {
        buf[i] = malloc(1 << i);
        memset(buf[i], 'C', 1 << i);
    }

    for (int i = 1; i < num; i++) {
        free(buf[i]);
    }

    debug_printf("end exp_malloc\n");
}

int main(int argc, char *argv[])
{
    printf("Morecore test spawned\n");

    lazy_malloc();
    malloc_free();
    malloc_then_free();
    m_f_m_f();
    exp_malloc();

    return EXIT_SUCCESS;
}
