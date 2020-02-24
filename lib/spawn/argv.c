#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <aos/aos.h>
#include <barrelfish_kpi/init.h>
#include <spawn/argv.h>

/**
 * \brief Tokenize the command line arguments and count them
 * 
 * \param cmdline The string to be parsed. Must not be NULL.
 * \param _argc Will be filled out with the number of arguments
 * found in 'cmdline'. Must not be NULL.
 * \param buf Will be filled out with a char array that contains 
 * the continuously in memory arranged arguments separated by '\0'.
 * (Note that there might also be some extra whitespace intbetween
 * the arguments.)
 * \return If 'cmdline' was parsed and tokenized successfully, argv
 * (an array of the arguments) will be returned, NULL otherwise.
 */
char ** make_argv(const char *cmdline, int *_argc, char **buf) {
    char **argv= calloc(MAX_CMDLINE_ARGS+1, sizeof(char *));
    if(!argv) return NULL;

    /* Carefully calculate the length of the command line. */
    size_t len= strnlen(cmdline, PATH_MAX+1);
    if(len > PATH_MAX) return NULL;

    /* Copy the command line, as we'll chop it up. */
    *buf= malloc(len + 1);
    if(!*buf) {
        free(argv);
        return NULL;
    }
    strncpy(*buf, cmdline, len + 1);
    (*buf)[len]= '\0';

    int argc= 0;
    size_t i= 0;
    while(i < len && argc < MAX_CMDLINE_ARGS) {
        /* Skip leading whitespace. */
        while(i < len && isspace((unsigned char)(*buf)[i])) i++;

        /* We may have just walked off the end. */
        if(i >= len) break;

        if((*buf)[i] == '"') {
            /* If the first character is ", then we need to scan until the
             * closing ". */

            /* The next argument starts *after* the opening ". */
            i++;
            argv[argc]= &(*buf)[i];
            argc++;

            /* Find the closing ". */
            while(i < len && (*buf)[i] != '"') i++;

            /* If we've found a ", overwrite it to null-terminate the string.
             * Otherwise, let the argument be terminated by end-of-line. */
            if(i < len) {
                (*buf)[i]= '\0';
                i++;
            }
        }
        else {
            /* Otherwise grab everything until the next whitespace
             * character. */

            /* The next argument starts here. */
            argv[argc]= &(*buf)[i];
            argc++;

            /* Find the next whitespace (if any). */
            while(i < len && !isspace((unsigned char)(*buf)[i])) i++;

            /* Null-terminate the string by overwriting the first whitespace
             * character, unless we're at the end, in which case the null at
             * the end of buf will terminate this argument. */
            if(i < len) {
                (*buf)[i]= '\0';
                i++;
            }
        }
    }
    /* (*buf)[argc] == NULL */

    *_argc= argc;
    return argv;
}
