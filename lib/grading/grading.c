#include <stdio.h>

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>
#include <aos/aos_rpc.h>
#include <grading.h>
#include <spawn/spawn.h>


void
grading_setup_bsp_init(int argc, char **argv) {
}

void
grading_setup_app_init(struct bootinfo * bi) {
}

void
grading_setup_noninit(int *argc, char ***argv) {
}

void
grading_test_mm(struct mm * test) {
}

void
grading_test_early(void) {
}

void
grading_test_late(void) {
}
