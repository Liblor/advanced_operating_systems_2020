
#include <stdio.h>
#include <aos/aos.h>
#include <aos/systime.h>
#include <fs/fs.h>
#include <fs/dirent.h>

static const char *fms[] = { "/sdcard/a512", "/sdcard/a1024", "/sdcard/a2048", "/sdcard/a4096" };
static char buf[4096];


errval_t write_test(uint64_t idx);
errval_t write_test(uint64_t idx) {
    FILE *f = fopen(fms[idx], "w");
    if (f == NULL) {
        return FS_ERR_OPEN;
    }
    uint64_t m = 16 << idx;
    uint64_t ticks_before = systime_now();
    for (int i = 0; i < m; i++) {
        fwrite("a", 1, 1, f);
    }
    fflush(f);
    uint64_t ticks_after = systime_now();
    fclose(f);
    printf("Timing FS (write): %lu %lu\n", m, systime_to_us(ticks_after - ticks_before));
    return SYS_ERR_OK;
}

errval_t read_test(uint64_t idx);
errval_t read_test(uint64_t idx) {
    FILE *f = fopen(fms[idx], "r");
    if (f == NULL) {
        return FS_ERR_OPEN;
    }
    uint64_t m = 16 << idx;
    uint64_t ticks_before = systime_now();
    fread(buf, 1, m, f);
    fflush(f);
    uint64_t ticks_after = systime_now();
    fclose(f);
    printf("Timing FS (read): %lu %lu\n", m, systime_to_us(ticks_after - ticks_before));
    return SYS_ERR_OK;
}

int main(int argc, char *argv[])
{
    printf("Started\n");
    filesystem_init();
    for (int j = 0; j < 20; ++j) {
        for (int i = 0; i < ARRAY_LENGTH(fms); i++) {
            write_test(i);
        }
    }
    for (int j = 0; j < 20; ++j) {
        for (int i = 0; i < ARRAY_LENGTH(fms); i++) {
            read_test(i);
        }
    }
    return EXIT_SUCCESS;
}
