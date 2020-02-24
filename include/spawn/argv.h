#ifndef __SPAWN_ARGV_H
#define __SPAWN_ARGV_H

// Split a command line into arguments (handles quoted strings).
// Returns a (modified) copy of cmdline in *buf.
char **make_argv(const char *cmdline, int *_argc, char **buf);

#endif /* __SPAWN_ARGV_H */
