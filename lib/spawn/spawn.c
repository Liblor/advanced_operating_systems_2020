#include <ctype.h>
#include <string.h>

#include <aos/aos.h>
#include <aos/debug.h>
#include <spawn/spawn.h>

#include <elf/elf.h>
#include <aos/dispatcher_arch.h>
#include <aos/lmp_chan.h>
#include <aos/aos_rpc.h>
#include <barrelfish_kpi/paging_arm_v8.h>
#include <barrelfish_kpi/domain_params.h>
#include <spawn/multiboot.h>
#include <spawn/argv.h>

extern struct bootinfo *bi;
extern coreid_t my_core_id;

/**
 * \brief Set the base address of the .got (Global Offset Table) section of the ELF binary
 *
 * \param arch_load_info This must be the base address of the .got section (local to the
 * child's VSpace). Must not be NULL.
 * \param handle The handle for the new dispatcher that is to be spawned. Must not be NULL.
 * \param enabled_area The "resume enabled" register set. Must not be NULL.
 * \param disabled_area The "resume disabled" register set. Must not be NULL.
 */
__attribute__((__used__))
static void armv8_set_registers(void *arch_load_info,
                              dispatcher_handle_t handle,
                              arch_registers_state_t *enabled_area,
                              arch_registers_state_t *disabled_area)
{
    assert(arch_load_info != NULL);
    uintptr_t got_base = (uintptr_t) arch_load_info;

    struct dispatcher_shared_aarch64 * disp_arm = get_dispatcher_shared_aarch64(handle);
    disp_arm->got_base = got_base;

    enabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
    disabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
}

static errval_t elf_allocator_cb(void *state, genvaddr_t base, size_t size, uint32_t flags, void **ret)
{
    errval_t err;

    struct elf_allocator_state *as = (struct elf_allocator_state *) state;

    /*
     * The base is not necessarily aligned, and neither is the end of the
     * segment. We have to choose base and corresponding size so that the
     * original bounds are included in our mapping, but the start and the end
     * of the mapping are aligned with BASE_PAGE_SIZE. In other words, we must
     * make sure that
     * - base_rounded is a multiple of BASE_PAGE_SIZE,
     * - base_rounded is less than the original base,
     * - end_rounded is a multiple of BASE_PAGE_SIZE, and
     * - end_rounded is greater than base + size.
     */

    const genvaddr_t base_rounded = ROUND_DOWN(base, BASE_PAGE_SIZE);
    const genvaddr_t end_rounded = ROUND_UP(base + size, BASE_PAGE_SIZE);
    const size_t size_rounded = end_rounded - base_rounded;

    // Allocate memory for the segment.
    struct capref segment_frame;
    size_t segment_bytes;
    err = frame_alloc(&segment_frame, size_rounded, &segment_bytes);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    assert(segment_bytes >= size);

    // Map the new memory into the VSpace of the child. Without mappings, the
    // child will die due to a page fault.
    err = paging_map_fixed_attr(as->paging_state_child, base_rounded, segment_frame, size_rounded, flags);
    if (err_is_fail(err)) {
        debug_printf("paging_map_fixed_attr() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    // Map the new memory into the VSpace of the parent. We need this for
    // writing the sections into the segments.
    void *mapped_parent;
    err = paging_map_frame_attr(get_current_paging_state(), &mapped_parent, size, segment_frame, VREGION_FLAGS_READ_WRITE, NULL, NULL);
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame_attr() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    // Return a pointer to the mapped memory. This is where the ELF loader will
    // write the section content. Note that we may deal with unaligned bases.
    *ret = mapped_parent + (base - base_rounded);

    return SYS_ERR_OK;
}

static inline errval_t load_module(struct spawninfo *si, void **module_data)
{
    errval_t err;

    // Map the module.
    struct capref child_frame = {
        .cnode = cnode_module,
        .slot = si->module->mrmod_slot,
    };
    err = paging_map_frame_attr(
        get_current_paging_state(),
        module_data,
        si->module->mrmod_size,
        child_frame,
        VREGION_FLAGS_READ,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame_attr() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    assert(IS_ELF(**(struct Elf64_Ehdr **) module_data));

    return SYS_ERR_OK;
}

static inline errval_t setup_cspace(struct capref *cap_cnode_l1, struct capref *l0_table_child, struct cnoderef *taskcn_child)
{
    errval_t err;

    err = cnode_create_l1(cap_cnode_l1, NULL);
    if (err_is_fail(err)) {
        debug_printf("cnode_create_l1() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CNODE_CREATE);
    }

    struct cnoderef *cnode_l2_rootcn_slot_taskcn = taskcn_child;
    struct cnoderef cnode_l2_rootcn_slot_alloc_0;
    struct cnoderef cnode_l2_rootcn_slot_alloc_1;
    struct cnoderef cnode_l2_rootcn_slot_alloc_2;
    struct cnoderef cnode_l2_rootcn_slot_base_page_cn;
    struct cnoderef cnode_l2_rootcn_slot_pagecn;

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_TASKCN, cnode_l2_rootcn_slot_taskcn);
    if (err_is_fail(err)) {
        debug_printf("cnode_create_foreign_l2() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CNODE_CREATE);
    }

    // Capability for the root CNode.
    struct capref slot_cnode_l1 = {
        .cnode = *taskcn_child,
        .slot = TASKCN_SLOT_ROOTCN,
    };
    err = cap_copy(slot_cnode_l1, *cap_cnode_l1);
    if (err_is_fail(err)) {
        debug_printf("cap_copy() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_SLOT_ALLOC0, &cnode_l2_rootcn_slot_alloc_0);
    if (err_is_fail(err)) {
        debug_printf("cnode_create_foreign_l2() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CNODE_CREATE);
    }

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_SLOT_ALLOC1, &cnode_l2_rootcn_slot_alloc_1);
    if (err_is_fail(err)) {
        debug_printf("cnode_create_foreign_l2() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CNODE_CREATE);
    }

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_SLOT_ALLOC2, &cnode_l2_rootcn_slot_alloc_2);
    if (err_is_fail(err)) {
        debug_printf("cnode_create_foreign_l2() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CNODE_CREATE);
    }

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_BASE_PAGE_CN, &cnode_l2_rootcn_slot_base_page_cn);
    if (err_is_fail(err)) {
        debug_printf("cnode_create_foreign_l2() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CNODE_CREATE);
    }

    struct capref cap_ram;

    err = ram_alloc(&cap_ram, L2_CNODE_SLOTS * BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        debug_printf("ram_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_RAM_ALLOC);
    }

    struct capref cap_start = {
        .cnode = cnode_l2_rootcn_slot_base_page_cn,
        .slot = 0,
    };

    err = cap_retype(cap_start, cap_ram, 0, ObjType_RAM, BASE_PAGE_SIZE, L2_CNODE_SLOTS);
    if (err_is_fail(err)) {
        debug_printf("cap_retype() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_PAGECN, &cnode_l2_rootcn_slot_pagecn);
    if (err_is_fail(err)) {
        debug_printf("cnode_create_foreign_l2() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CNODE_CREATE);
    }

    l0_table_child->cnode = cnode_l2_rootcn_slot_pagecn;
    l0_table_child->slot = 0;

    return SYS_ERR_OK;
}

static inline errval_t setup_vspace(struct capref l0_table_child, struct paging_state *paging_state_child)
{
    errval_t err;

    struct capref l0_table_parent;
    err = slot_alloc(&l0_table_parent);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    err = vnode_create(l0_table_parent, ObjType_VNode_AARCH64_l0);
    if (err_is_fail(err)) {
        debug_printf("vnode_create() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VNODE_CREATE);
    }

    err = cap_copy(l0_table_child, l0_table_parent);
    if (err_is_fail(err)) {
        debug_printf("cap_copy() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    err = paging_init_state_foreign(paging_state_child, BASE_PAGE_SIZE, l0_table_parent, get_default_slot_allocator());
    if (err_is_fail(err)) {
        debug_printf("paging_init_state_foreign() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_INITIALIZATION);
    }

    return SYS_ERR_OK;
}

static inline errval_t parse_elf(struct mem_region *module, void *module_data, struct elf_allocator_state *as, genvaddr_t *entry_point_addr, void **got_section_addr)
{
    errval_t err;

    err = elf_load(
        EM_AARCH64,
        elf_allocator_cb,
        as,
        (lvaddr_t) module_data,
        module->mrmod_size,
        entry_point_addr
    );
    if (err_is_fail(err)) {
        debug_printf("elf_load() failed: %s\n", err_getstring(err));
        return err_push(err, SPAWN_ERR_ELF_MAP);
    }

    struct Elf64_Shdr *got;
    got = elf64_find_section_header_name((genvaddr_t) module_data, module->mrmod_size, ".got");
    if (got == NULL) {
        debug_printf("elf_load() failed\n");
        return SPAWN_ERR_ELF_MAP;
    }

    *got_section_addr = (void *) got->sh_addr;

    return SYS_ERR_OK;
}

static inline errval_t setup_arguments(struct paging_state *paging_state_child, int argc, char *argv[], struct cnoderef taskcn_child, void **args_page_child)
{
    errval_t err;

    struct capref args_frame;
    size_t args_frame_size;
    void *args_page_parent;

    // TODO: Is BASE_PAGE_SIZE always large enough?
    err = frame_alloc(&args_frame, BASE_PAGE_SIZE, &args_frame_size);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    assert(args_frame_size >= BASE_PAGE_SIZE);

    err = paging_map_frame_attr(
        get_current_paging_state(),
        &args_page_parent,
        args_frame_size,
        args_frame,
        VREGION_FLAGS_READ_WRITE,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame_attr() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    err = paging_map_frame_attr(
        paging_state_child,
        args_page_child,
        args_frame_size,
        args_frame,
        VREGION_FLAGS_READ_WRITE,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame_attr() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    struct capref args_frame_child = {
        .cnode = taskcn_child,
        .slot = TASKCN_SLOT_ARGSPAGE,
    };

    err = cap_copy(args_frame_child, args_frame);
    if (err_is_fail(err)) {
        debug_printf("cap_copy() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    struct spawn_domain_params *params = (struct spawn_domain_params *) args_page_parent;

    // Everything that is not set explicitly should be zero.
    memset(args_page_parent, 0, args_frame_size);

    char *argv_data = args_page_parent + sizeof(struct spawn_domain_params);

    for (int i = 0; i < argc; i++) {
        strcpy(argv_data, argv[i]);
        int n = strlen(argv[i]) + 1;
        params->argv[i] = argv_data - (char *)args_page_parent + *args_page_child;
        argv_data += n;
    }

    params->argc = argc;
    params->argv[argc] = NULL;
    params->envp[0] = NULL;
    params->vspace_buf = NULL;
    params->vspace_buf_len = 0;
    params->tls_init_base = NULL;
    params->tls_init_len = 0;
    params->tls_total_len = 0;
    params->pagesize = 0;

    return SYS_ERR_OK;
}

static inline errval_t setup_dispatcher(struct paging_state *ps, char *name, struct capref *dp_child, void *got_section_addr, genvaddr_t entry_point_addr, void *args_page_child, struct capref *dp_frame_child, struct cnoderef taskcn_child)
{
    errval_t err;

    err = slot_alloc(dp_child);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    err = dispatcher_create(*dp_child);
    if (err_is_fail(err)) {
        debug_printf("dispatcher_create() failed: %s\n", err_getstring(err));
        return err_push(err, SPAWN_ERR_CREATE_DISPATCHER);
    }

    size_t dp_frame_bytes;
    struct capref dp_frame_parent;

    err = frame_alloc(&dp_frame_parent, DISPATCHER_FRAME_SIZE, &dp_frame_bytes);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    assert(dp_frame_bytes >= DISPATCHER_FRAME_SIZE);

    // Endpoint to the dispatcher itself.
    struct capref slot_selfep = {
        .cnode = taskcn_child,
        .slot = TASKCN_SLOT_SELFEP,
    };
    err = cap_retype(slot_selfep, *dp_child, 0, ObjType_EndPointLMP, 0, 1);
    if (err_is_fail(err)) {
        debug_printf("cap_retype() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_RETYPE);
    }

    // Dispatcher capability.
    struct capref slot_dp = {
        .cnode = taskcn_child,
        .slot = TASKCN_SLOT_DISPATCHER,
    };
    err = cap_copy(slot_dp, *dp_child);
    if (err_is_fail(err)) {
        debug_printf("cap_copy() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    // Capability to the dispatcher frame.
    dp_frame_child->cnode = taskcn_child;
    dp_frame_child->slot = TASKCN_SLOT_DISPFRAME;

    err = cap_copy(*dp_frame_child, dp_frame_parent);
    if (err_is_fail(err)) {
        debug_printf("cap_copy() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    // Map dispatcher into parent.
    void *dp_page_parent;
    err = paging_map_frame_attr(
        get_current_paging_state(),
        &dp_page_parent,
        dp_frame_bytes,
        dp_frame_parent,
        VREGION_FLAGS_READ_WRITE,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame_attr() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    // Map dispatcher into child.
    void *dp_page_child;
    err = paging_map_frame_attr(
        ps,
        &dp_page_child,
        dp_frame_bytes,
        dp_frame_parent,
        VREGION_FLAGS_READ_WRITE,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame_attr() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    dispatcher_handle_t handle_child = (dispatcher_handle_t) dp_page_parent;
    struct dispatcher_shared_generic *disp_child = get_dispatcher_shared_generic(handle_child);
    struct dispatcher_generic *disp_gen = get_dispatcher_generic(handle_child);
    arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area(handle_child);
    arch_registers_state_t *disabled_area = dispatcher_get_disabled_save_area(handle_child);

    disp_gen->core_id = my_core_id;
    disp_child->udisp = (lvaddr_t) dp_page_child;
    disp_child->disabled = 1;
    strncpy(disp_child->name, name, DISP_NAME_LEN);
    registers_set_entry(disabled_area, entry_point_addr);

    // The args are currently read from the enabled area. I believe this is a
    // bug, so we write the arguments page in both areas for now.
    registers_set_param(enabled_area, (uint64_t) args_page_child);
    registers_set_param(disabled_area, (uint64_t) args_page_child);

    armv8_set_registers(got_section_addr, handle_child, enabled_area, disabled_area);
    disp_gen->eh_frame = 0;
    disp_gen->eh_frame_size = 0;
    disp_gen->eh_frame_hdr = 0;
    disp_gen->eh_frame_hdr_size = 0;

    return SYS_ERR_OK;
}

/**
 * \brief Spawn a new dispatcher called 'argv[0]' with 'argc' arguments.
 *
 * This function spawns a new dispatcher running the ELF binary called
 * 'argv[0]' with 'argc' - 1 additional arguments. It fills out 'si'
 * and 'pid'.
 *
 * \param argc The number of command line arguments. Must be > 0.
 * \param argv An array storing 'argc' command line arguments.
 * \param si A pointer to the spawninfo struct representing
 * the child. It will be filled out by this function. Must not be NULL.
 * \param pid A pointer to a domainid_t variable that will be
 * assigned to by this function. Must not be NULL.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid)
{
    errval_t err;

    // TODO: Fill the struct domainid_t argument.

    // Initialize the spawninfo struct.
    si->next = NULL;
    si->binary_name = argv[0];

    void *module_data;
    err = load_module(si, &module_data);
    if (err_is_fail(err)) {
        debug_printf("load_module() failed: %s\n", err_getstring(err));
        return err_push(err, SPAWN_ERR_LOAD);
    }

    struct capref cap_cnode_l1;
    struct capref l0_table_child;
    struct cnoderef taskcn_child;

    err = setup_cspace(&cap_cnode_l1, &l0_table_child, &taskcn_child);
    if (err_is_fail(err)) {
        debug_printf("setup_cspace() failed: %s\n", err_getstring(err));
        return err_push(err, SPAWN_ERR_SETUP_CSPACE);
    }

    struct elf_allocator_state as;
    as.paging_state_child = malloc(sizeof(struct paging_state));

    err = setup_vspace(l0_table_child, as.paging_state_child);
    if (err_is_fail(err)) {
        debug_printf("setup_vspace() failed: %s\n", err_getstring(err));
        return err_push(err, SPAWN_ERR_VSPACE_INIT);
    }

    genvaddr_t entry_point_addr;
    void *got_section_addr;

    err = parse_elf(si->module, module_data, &as, &entry_point_addr, &got_section_addr);
    if (err_is_fail(err)) {
        debug_printf("parse_elf() failed: %s\n", err_getstring(err));
        return err_push(err, SPAWN_ERR_ELF_MAP);
    }

    void *args_page_child;

    err = setup_arguments(as.paging_state_child, argc, argv, taskcn_child, &args_page_child);
    if (err_is_fail(err)) {
        debug_printf("setup_arguments() failed: %s\n", err_getstring(err));
        return err_push(err, SPAWN_ERR_SETUP_ENV);
    }

    struct capref dp_child;
    struct capref dp_frame_child;

    err = setup_dispatcher(as.paging_state_child, si->binary_name, &dp_child, got_section_addr, entry_point_addr, args_page_child, &dp_frame_child, taskcn_child);
    if (err_is_fail(err)) {
        debug_printf("setup_dispatcher() failed: %s\n", err_getstring(err));
        return err_push(err, SPAWN_ERR_SETUP_DISPATCHER);
    }

    err = invoke_dispatcher(dp_child, cap_dispatcher, cap_cnode_l1, l0_table_child, dp_frame_child, true);
    if (err_is_fail(err)) {
        debug_printf("invoke_dispatcher() failed: %s\n", err_getstring(err));
        return err_push(err, SPAWN_ERR_DISPATCHER_SETUP);
    }

    return SYS_ERR_OK;
}

/**
 * \brief Spawn a new dispatcher executing 'binary_name'
 *
 * \param binary_name The name of the binary.
 * \param si A pointer to a spawninfo struct that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 * \param pid A pointer to a domainid_t that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 *
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_by_name(char *binary_name, struct spawninfo * si, domainid_t *pid)
{
    // TODO: Return an error instead.
    assert(si != NULL);
    assert(pid != NULL);

    errval_t err;

    // Get the mem_region from the multiboot image.
    si->module = multiboot_find_module(bi, binary_name);
    if (si->module == NULL) {
        debug_printf("multiboot_find_module() failed\n");
        return SPAWN_ERR_FIND_MODULE;
    }

    const char *opts = multiboot_module_opts(si->module);
    if (opts == NULL) {
        debug_printf("multiboot_module_opts() failed\n");
        return SPAWN_ERR_GET_CMDLINE_ARGS;
    }

    int argc;
    char *buf;
    char **argv = make_argv(opts, &argc, &buf);
    if (argv == NULL) {
        debug_printf("make_argv() failed\n");
        return SPAWN_ERR_GET_CMDLINE_ARGS;
    }

    err = spawn_load_argv(argc, argv, si, pid);
    if (err_is_fail(err)) {
        debug_printf("spawn_load_argv() failed: %s\n", err_getstring(err));
        return err_push(err, SPAWN_ERR_LOAD);
    }

    return SYS_ERR_OK;
}
