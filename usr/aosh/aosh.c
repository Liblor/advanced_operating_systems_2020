//
// Created by b on 5/18/20.
//

#include <stdio.h>
#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/string.h>
#include <collections/list.h>

#include "aosh.h"
#include "builtin/builtin.h"

#define err_is_fail(err) ((err_is_fail(err) ? (HERE, true) : false))


static struct aosh_state aosh;

static errval_t aosh_init(void)
{
    memset(&aosh, 0, sizeof(struct aosh_state));
    return SYS_ERR_OK;
}

static bool aosh_err_recoverable(errval_t err)
{
    return err == SYS_ERR_OK ||
           err == AOSH_ERR_INVALID_ESCAPE_CHAR ||
           err == AOSH_ERR_INVALID_ARGS ||
           err == AOSH_ERR_BUILTIN_EXIT_SUCCESS;
}

__unused
static void clear_screen(void)
{
    printf("\e[1;1H\e[2J");
    fflush(stdout);
}

__unused
static void trace_args(
        int argc,
        char **argv)
{
    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = '%s'" ENDL, i, argv[i]);
    }
}

static void free_argv(
        int argc,
        char **argv)
{
    if (argv == NULL) {
        return;
    }
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
}

/** Read a line from serial port,
 * caller must free line.
 * On success, line is always null terminated **/
static errval_t aosh_readline(
        void **ret_line,
        size_t *ret_size)
{
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    char *buf = calloc(1, AOSH_READLINE_MAX_LEN);
    if (buf == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    char c = 0;
    int i = 0;
    errval_t err;

    while (i < AOSH_READLINE_MAX_LEN) {
        err = aos_rpc_lmp_serial_getchar(rpc, &c);
        if (err_is_fail(err)) {
            goto free_buf;
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
    }
    if (c == CHAR_CODE_EOT) {
        // ctrl d  pressed
        err = AOSH_ERR_EXIT_SHELL;
        goto free_buf;
    }
    assert(i <= AOSH_READLINE_MAX_LEN);

    *ret_line = calloc(1, i);
    if (*ret_line == NULL) {
        err = LIB_ERR_MALLOC_FAIL;
        goto free_buf;
    }

    strlcpy((*ret_line), buf, i);
    if (ret_size != NULL) {
        *ret_size = i;
    }
    err = SYS_ERR_OK;

    free_buf:
    free(buf);
    return err;
}

static __inline bool is_quote_start(
        int arg_start,
        const char *line)
{
    const bool quote_first_char =
            line[arg_start] == '"' && arg_start == 0;
    const bool quote_not_escaped =
            line[arg_start] == '"' && arg_start > 0 && line[arg_start - 1] != '\\';

    return quote_first_char || quote_not_escaped;
}

/**
 * simple arg tokenize implementation
 * - supports double quotes for strings with spaces
 * - and escape of quotes
 *
 * note: ret_argv must be freed;
 * every entry within ret_argv as well as ret_argv itself
 */
static errval_t aosh_tokenize_arg(
        const char *line,
        int *ret_argc,
        char ***ret_argv)
{
    errval_t err;
    collections_listnode *argv_list = NULL;
    collections_list_create(&argv_list, NULL);
    if (argv_list == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    int arg_start = 0;
    bool quote_double = false;
    for (int i = 0; i < AOSH_READLINE_MAX_LEN; i++) {
        AOSH_TRACE("parsing line[%d]='%d' \n", i, line[i]);

        if ((!quote_double && line[i] == ' ')
            || line[i] == '\0'
            || IS_CHAR_LINEBREAK(line[i])) {

            // XXX dont include quotes in argument
            if (is_quote_start(arg_start, line)) {
                arg_start++;
            }
            int arg_end = i;
            if (i > 1 && line[i - 1] == '"') {
                arg_end--;
            }

            const size_t arg_len  = arg_end - arg_start + 1; // +1 for \0

            // XXX empty spaces should not cause empty
            // args so we skip empty spaces here
            if (arg_len == 1 &&
                line[i] == ' ') {
                arg_start = i + 1;
                continue;
            }

            void *arg = calloc(1, arg_len);
            if (arg == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }

            strlcpy(arg, &line[arg_start], arg_len);
            if (collections_list_insert_tail(argv_list, arg) != 0) {
                // XXX: if this fails something bad happened with malloc
                // no need to proper free
                return LIB_ERR_MALLOC_FAIL;
            }
            arg_start = i + 1;

            if (line[i] == '\0' || IS_CHAR_LINEBREAK(line[i])) {
                break;
            }
        } else if ((line[i] == '"' && i > 1 && line[i - 1] != '\\')
                   || (line[i] == '"' && i == 0)) {
            // dont tokenize within quotes
            quote_double = !quote_double;
        }
        AOSH_TRACE("line[%d]='%c'\n", i, line[i]);
    }

    const int argc = collections_list_size(argv_list);
    *ret_argv = calloc(1, argc * sizeof(char **));
    if (ret_argv == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    *ret_argc = argc;
    for (int i = 0; i < argc; i++) {
        (*ret_argv)[i] = collections_list_get_ith_item(argv_list, i);
        AOSH_TRACE("*ret_argv[%i]='%s'\n", i, (*ret_argv)[i]);
    }
    if (quote_double) {
        err = AOSH_ERR_INVALID_ESCAPE_CHAR;
        goto free_argv_list;
    }
    err = SYS_ERR_OK;

    free_argv_list:
    collections_list_release(argv_list);
    return err;
}

__unused
static errval_t aosh_dispatch(
        char *line,
        int argc,
        char **argv)
{
    errval_t err = aosh_dispatch_builtin(argc, argv);
    if (err == AOSH_ERR_EXIT_SHELL) {
        return err;
    }
    if (!err_is_ok(err)) {
        debug_printf("error executing %s: %s\n", argv[0], err_getstring(err));
    }
    return SYS_ERR_OK;
}

static errval_t aosh_read_eval_execute(void)
{
    errval_t err;
    char *line = NULL;
    char **argv = NULL;
    int argc = 0;
    size_t line_size = 0;
    HERE;
    printf(AOSH_CLI_HEAD);
    fflush(stdout);

    err = aosh_readline((void **) &line, &line_size);
    printf(ENDL);

    if (err == AOSH_ERR_EXIT_SHELL) {
        goto err_free_line;
    } else if (err_is_fail(err)) {
        debug_printf("failed to aosh_readline. %s\n", err_getstring(err));
        goto err_free_line;
    }
    if (line_size <= 1) { // \0
        // nothing read;
        goto success_free;
    }

    err = aosh_tokenize_arg(line, &argc, &argv);
    if (!aosh_err_recoverable(err)) {
        goto err_free;
    }
    if (err == AOSH_ERR_INVALID_ESCAPE_CHAR) {
        printf("Invalid combination of quotes given." ENDL);
        trace_args(argc, argv);
        goto success_free;
    }
    err = aosh_dispatch(line, argc, argv);
    if (!err_is_ok(err)) {
        goto err_free;
    }

    success_free:
    free(line);
    free_argv(argc, argv);
    line = NULL;
    argv = NULL;
    argc = 0;

    return SYS_ERR_OK;

    err_free:
    free_argv(argc, argv);
    err_free_line:
    free(line);
    return err;
}

int main(
        int argc,
        char *argv[])
{
    errval_t err;
    printf("spawning aosh..." ENDL);

    err = aosh_init();
    if (err_is_fail(err)) {
        debug_printf("failed to init aosh. %s", err_getstring(err));
        return EXIT_FAILURE;
    }
    // clear_screen();
    printf("Welcome to aosh! "ENDL);

    do {
        err = aosh_read_eval_execute();
        thread_yield();
    } while (err_is_ok(err));

    if (err == AOSH_ERR_EXIT_SHELL) {
        printf("Goodbye. It was a pleasure to have fought along your side." ENDL);
        return EXIT_SUCCESS;

    } else if (err_is_fail(err)) {
        debug_printf("aosh repl failed: %s\n", err_getstring(err));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}