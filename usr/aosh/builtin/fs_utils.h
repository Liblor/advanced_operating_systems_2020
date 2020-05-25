//
// Created by b on 5/25/20.
//

#ifndef BFOS_FS_UTILS_H
#define BFOS_FS_UTILS_H

errval_t builtin_ls(int argc, char **argv);
errval_t builtin_cat(int argc, char **argv);
errval_t builtin_cd(int argc, char **argv);
errval_t builtin_mkdir(int argc, char **argv);
errval_t rmdir(int argc, char **argv);
errval_t touch(int argc, char **argv);

#endif //BFOS_FS_UTILS_H
