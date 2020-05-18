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

static struct aosh_state aosh;

static errval_t aosh_init(void)
{
    memset(&aosh, 0, sizeof(struct aosh_state));
    return SYS_ERR_OK;
}

static bool aosh_err_recoverable(errval_t err)
{
    return err == SYS_ERR_OK ||
           err == AOS_ERR_AOSH_INVALID_ESCAPE_CHAR;
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

/** read a line from serial port,
 *  caller must free line  **/
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
        buf[i - 1] = '\0';
    }
    if (c == CHAR_CODE_EOT) {
        // ctrl d  pressed
        err = AOS_ERR_AOSH_EXIT;
        goto free_buf;
    }
    assert(i <= AOSH_READLINE_MAX_LEN);

    *ret_line = calloc(1, i);
    if (*ret_line == NULL) {
        err = LIB_ERR_MALLOC_FAIL;
        goto free_buf;
    }

    memcpy(*ret_line, buf, i);
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
            line[arg_start] == '"' && arg_start > 0 && line[arg_start - 1] == '\\';

    return quote_first_char || quote_not_escaped;
}

/** note: ret_argv must be freed;
 * every entry within ret_argv as well as ret_argv itself **/
static errval_t tokenize_argv(
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

        if ((!quote_double && line[i] == ' ')    // no arg in quotes, space tokenizes
            || line[i] == '\0'
            || IS_CHAR_LINEBREAK(line[i])) {

            if (is_quote_start(arg_start, line)) {
                arg_start++;
            }
            int arg_end = i;
            if (i > 1 && line[i - 1] == '"') {
                arg_end--;
            }

            size_t len = arg_end - arg_start + 1; // +1 for \0
            void *arg = calloc(1, len);
            if (arg == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }
            strlcpy(arg, &line[arg_start], len);
            int succ = collections_list_insert_tail(argv_list, arg);
            if (succ != 0) {
                // XXX: if this fails something bad happened with malloc
                // no need to proper free
                return COLLECTIONS_COLLECTIONS_LIST_INSERT_TAIL_FAILED;
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
        err = AOS_ERR_AOSH_INVALID_ESCAPE_CHAR;
        goto free_argv_list;
    }
    err = SYS_ERR_OK;

    free_argv_list:
    collections_list_release(argv_list);
    return err;
}

__unused
static errval_t execute(
        char *line,
        int argc,
        char **argv)
{
    errval_t err = aosh_dispatch_builtin(argc, argv);
    if (err == AOS_ERR_AOSH_EXIT) {
        return err;
    }
    if (!err_is_ok(err)) {
        debug_printf("error executing %s: %s\n", argv[0], err_getstring(err));
    }
    return SYS_ERR_OK;
}

static errval_t read_eval_execute(void)
{
    errval_t err;
    char *line = NULL;
    char **argv = NULL;
    int argc = 0;

    printf(AOSH_CLI_HEAD);
    fflush(stdout);

    err = aosh_readline((void **) &line, NULL);
    printf(ENDL);

    if (err == AOS_ERR_AOSH_EXIT) {
        goto err_free_line;
    } else if (err_is_fail(err)) {
        debug_printf("failed to aosh_readline. %s\n", err_getstring(err));
        goto err_free_line;
    }

    err = tokenize_argv(line, &argc, &argv);
    if (!aosh_err_recoverable(err)) {
        goto err_free;
    }
    if (err == AOS_ERR_AOSH_INVALID_ESCAPE_CHAR) {
        printf("Invalid combination of quotes given." ENDL);
        trace_args(argc, argv);
        goto success_free;
    }

    err = execute(line, argc, argv);
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
        err = read_eval_execute();
    } while (err_is_ok(err));

    if (err == AOS_ERR_AOSH_EXIT) {
        printf("Goodbye. It was a pleasure to have fought along your side." ENDL);
        return EXIT_SUCCESS;

    } else if (err_is_fail(err)) {
        debug_printf("aosh repl failed: %s\n", err_getstring(err));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}