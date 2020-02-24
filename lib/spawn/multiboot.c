
#include <aos/aos.h>
#include <assert.h>
#include <string.h>

#include <spawn/multiboot.h>

static char * multiboot_strings;

/**
 * \brief Get the command line arguments of a multiboot module as a raw string
 * 
 * This function returns a raw pointer into the multiboot_strings array.
 * The pointer points to the first char of the first argument of the multi-
 * boot module. That is always the filename of the binary.
 * 
 * \param module A pointer to a mem_region struct corresponding to a
 * multiboot module. Must not be NULL.
 * \return A raw pointer into the multiboot_strings array.
 */
const char *multiboot_module_opts(struct mem_region *module)
{
    assert(module != NULL);
    assert(module->mr_type == RegionType_Module);

    const char *optstring = multiboot_module_rawstring(module);

    // find the first space (or end of string if there is none)
    const char *args = strchr(optstring, ' ');
    if (args == NULL) {
        args = optstring + strlen(optstring);
    }

    // search backward for last '/' before the first ' '
    for (const char *c = args; c > optstring; c--) {
        if (*c == '/') {
            return c + 1;
        }
    }

    return optstring;
}

/**
 * \brief Returns a raw pointer to the modules string area string
 * 
 * \param region A pointer the the mem_region struct of a multiboot module.
 * \return A raw pointer into the multiboot_strings array or NULL.
 */
const char *multiboot_module_rawstring(struct mem_region *region)
{
    if (multiboot_strings == NULL) {
        errval_t err;
        /* Map in multiboot module strings area */
        err = paging_map_frame_attr(get_current_paging_state(),
            (void **)&multiboot_strings, BASE_PAGE_SIZE, cap_mmstrings,
            VREGION_FLAGS_READ, NULL, NULL);

        if (err_is_fail(err)) {
            DEBUG_ERR(err, "vspace_map failed");
	        return NULL;
        }
#if 0
        printf("Mapped multiboot_strings at %p\n", multiboot_strings);
        for (int i = 0; i < 256; i++) {
            if ((i & 15) == 0) printf("%04x  ", i);
            printf ("%02x ", multiboot_strings[i]& 0xff);
            if ((i & 15) == 15) printf("\n");
        }
#endif
    }

    if (region == NULL || region->mr_type != RegionType_Module) {
        return NULL;
    }
    return multiboot_strings + region->mrmod_data;
}

/**
 * \brief Returns the basename of 'region' without arguments
 * 
 * This function returns the basename of a multiboot module.
 * As it is returned in a static char buffer, it is advised
 * to copy the basename for continued use after calling this
 * function.
 * 
 * XXX: returns pointer to static buffer. NOT THREAD SAFE
 * 
 * \param region A pointer to the mem_region struct of a
 * multiboot module.
 * \return A pointer to a static char buffer cointaining the
 * basenamemof 'region' ('\0' terminated) or NULL.
 */
const char *multiboot_module_name(struct mem_region *region)
{
    const char *str = multiboot_module_rawstring(region);
    if (str == NULL) {
	return NULL;
    }

    // copy module data to local buffer so we can mess with it
    static char buf[128];
    strncpy(buf, str, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0'; // ensure termination

    // ignore arguments for name comparison
    char *args = strchr(buf, ' ');
    if (args != NULL) {
        *args = '\0';
    }

    return buf;
}

/**
 * \brief Returns a pointer to the mem_region struct corresponding to the binary 'name'
 * 
 * This function returns a pointer to the mem_region struct stored in the bootinfo
 * struct's memory regions array that corresponds to 'name'. 'name' can either be
 * the absolute path of a binary (starting with '/') or simply the relative path of
 * the binary (relative to the directory build/armv8/sbin/).
 * 
 * \param bi A pointer to the bootinfo struct, must not be NULL.
 * \param name A string corresponding to the absolute or relative path of a binary.
 * Must not be NULL.
 * \return A pointer to the memory_region struct of the binary 'name' or NULL.
 */
struct mem_region *multiboot_find_module(struct bootinfo *bi, const char *name)
{
    // absolute paths starting with /
    size_t len = strlen(name)+1;

    if (name[0] != '/') {
        /* relative path within armv8/sbin/*/
        len += strlen("/armv8/sbin/");
    }

    char pathname[len];
    if (name[0] != '/') {
        snprintf(pathname, len, "/armv8/sbin/%s", name);
        name = pathname;
    }
    DEBUG_PRINTF("name is: %s\n", name);
    for(size_t i = 0; i < bi->regions_length; i++) {
        struct mem_region *region = &bi->regions[i];
        const char *modname = multiboot_module_name(region);
        if (modname != NULL &&
            strcmp(modname, name) == 0) {
            return region;
        }
    }

    return NULL;
}
