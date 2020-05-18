//
// Created by b on 5/18/20.
//

#include <stdio.h>
#include <aos/aos.h>
#include <aos/debug.h>


#include <aos/string.h>
#include "aosh.h"

static struct aosh_state aosh;

static errval_t aosh_init(void)
{
    memset(&aosh, 0, sizeof(struct aosh_state));
    return SYS_ERR_OK;
}

__unused
static
void aosh_clear_screen(void)
{
    printf("\e[1;1H\e[2J");
    fflush(stdout);
}

#define AOSH_READLINE_MAX_LEN 128

__inline
static errval_t aosh_readline(
        void **ret_line,
        size_t *ret_size
)
{
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    char c;
    char buf[AOSH_READLINE_MAX_LEN];
    int i = 0;
    errval_t err;

    while (i < AOSH_READLINE_MAX_LEN) {
        err = aos_rpc_lmp_serial_getchar(rpc, &c);
        if (err_is_fail(err)) {
            return err;
        }
        if (IS_CHAR_LINEBREAK(c)) {
            buf[i] = '\0';
            i++;
            break;
        } else {
            buf[i] = c;
            i++;
            printf("%c", c);
            fflush(stdout);
        }
    }
    if (i == AOSH_READLINE_MAX_LEN) {
        debug_printf("AOSH_READLINE_MAX_LEN reached. truncating line\n");
        buf[i - 1] = '\0';
    }
    if (c == CHAR_CODE_EOT) { // ctrl d {
        return AOS_ERR_AOSH_EXIT;
    }
    assert(i <= AOSH_READLINE_MAX_LEN);

    *ret_line = malloc(i);
    if (*ret_line == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    memcpy(*ret_line, &buf, i);
    if (ret_size != NULL) {
        *ret_size = i;
    }
    return SYS_ERR_OK;
}


__unused
static errval_t example(int argc, char *argv[])
{

    return SYS_ERR_OK;
}

//static errval_t tokenize_argv(const char *line,)

__unused
static errval_t evaluate(
        const char *line
)
{
    char buf[AOSH_READLINE_MAX_LEN];
    char *argv[AOSH_READLINE_MAX_LEN];
    int bufi = 0;
    int argc = 0;
    int buf_start = 0;
    bool escape_double = false;

    for (int i = 0; i < AOSH_READLINE_MAX_LEN; i++) {
        if ((!escape_double && line[i] == ' ') || line[i] == '\0') {
            // spaces or end of str
            buf[bufi] = '\0';
            argv[argc] = &buf[buf_start];
            bufi++;
            buf_start = bufi;
            argc++;

            if (line[i] == '\0') {
                // end of str
                break;
            }

        } else if (IS_CHAR_LINEBREAK(line[i])) {
            // newlines
            break;
        } else if ((line[i] == '"' && i > 1 && line[i - 1] != '\\')
                   || (line[i] == '"' && i == 0)) {
            // quotation (") which is not escaped signalizes a string
            // we dont add (") into the list of parsed args
            escape_double = !escape_double;

            bufi++;
        } else {
            // all other chars
            buf[bufi] = line[i];
            bufi++;
        }
    }
    if (escape_double) {
        printf("Error in escaping characters" ENDL);
        printf("argument line: '%s'"ENDL, line);
        for (int i = 0; i < argc; i++) {
            printf("argv[%d] = '%s'" ENDL, i, argv[i]);
        }
        return AOS_ERR_AOSH_INVALID_ESCAPE_CHAR;
    }

    printf("argument line: '%s'"ENDL, line);
    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = '%s'" ENDL, i, argv[i]);
    }

    return SYS_ERR_OK;
}

static bool aosh_err_recoverable(errval_t err)
{
    return err == SYS_ERR_OK ||
           err == AOS_ERR_AOSH_INVALID_ESCAPE_CHAR ||
           err == AOS_ERR_AOSH_EXIT;
}

static errval_t repl(void)
{
    errval_t err;

    char *line = NULL;
    size_t size = 0;
    while (1) {
        printf("aosh >>> ");
        fflush(stdout);

        err = aosh_readline((void **) &line, &size);
        if (err == AOS_ERR_AOSH_EXIT) {
            free(line);
            return err;
        }
        if (err_is_fail(err)) {
            debug_printf("failed to aosh_readline. %s\n", err_getstring(err));
            goto err_free_line;
        }
        if (line == NULL) {
            err = LIB_ERR_MALLOC_FAIL;
            debug_printf("failed to aosh_readline. line is NULL\n");
            goto err_free_line;
        }

        printf(ENDL);
        // err = evaluate(line);
        if (!aosh_err_recoverable(err)) {
            goto err_free_line;
        }
        free(line);
    }
    return SYS_ERR_OK;

    err_free_line:
    free(line);
    return err;
}

int main(int argc, char *argv[])
{
    errval_t err;
    printf("spawning aosh..." ENDL);

    err = aosh_init();
    if (err_is_fail(err)) {
        debug_printf("failed to init aosh. %s", err_getstring(err));
        return EXIT_FAILURE;
    }
    aosh_clear_screen();
    printf("Welcome to aosh! "ENDL);
    err = repl();

    if (err == AOS_ERR_AOSH_EXIT) {
        printf("Goodbye. It was a pleasure to have fought along your side." ENDL);
        return EXIT_SUCCESS;
    } else if (err_is_fail(err)) {
        debug_printf("aosh repl failed: %s\n", err_getstring(err));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}