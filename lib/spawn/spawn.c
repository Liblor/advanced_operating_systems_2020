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

static inline errval_t fill_taskcn(struct capref dp, struct capref dp_frame, struct cnoderef taskcn, struct capref cnode_l1)
{
    errval_t err;

    // Endpoint to the dispatcher itself.
    struct capref slot_selfep = {
        .cnode = taskcn,
        .slot = TASKCN_SLOT_SELFEP,
    };
    err = cap_retype(slot_selfep, dp, 0, ObjType_EndPointLMP, 0, 1);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    // Dispatcher capability.
    struct capref slot_dp = {
        .cnode = taskcn,
        .slot = TASKCN_SLOT_DISPATCHER,
    };
    err = cap_copy(slot_dp, dp);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    // Capability for the root CNode.
    struct capref slot_cnode_l1 = {
        .cnode = taskcn,
        .slot = TASKCN_SLOT_ROOTCN,
    };
    err = cap_copy(slot_cnode_l1, cnode_l1);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    // Capability to the dispatcher frame.
    struct capref slot_dp_frame = {
        .cnode = taskcn,
        .slot = TASKCN_SLOT_DISPFRAME,
    };
    err = cap_copy(slot_dp_frame, dp_frame);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}

static errval_t elf_allocator_func(void *state, genvaddr_t base, size_t size, uint32_t flags, void **ret)
{
    errval_t err;

    struct elf_allocator_state *as = (struct elf_allocator_state *) state;

    // Allocate memory.
    struct capref portion_frame;
    size_t portion_bytes;
    err = frame_alloc(&portion_frame, size, &portion_bytes);
    // TODO: Return an error instead.
    assert(err_is_ok(err));
    assert(portion_bytes >= size);

    // Map the new memory into the VSpace of the child.
    void *mapped_child;
    err = paging_map_frame_attr(&as->paging_state_child, &mapped_child, size, portion_frame, flags, NULL, NULL);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    // Map the new memory into the VSpace of the parent.
    void *mapped_parent;
    err = paging_map_frame_attr(get_current_paging_state(), &mapped_parent, size, portion_frame, flags, NULL, NULL);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    // Return a pointer to the mapped memory.
    *ret = mapped_parent;

    return SYS_ERR_OK;
}

static inline errval_t load_module(char *name, struct mem_region **module, void **module_data)
{
    errval_t err;

    // Get the module from the multiboot image.
    *module = multiboot_find_module(bi, name);
    // TODO: Return an error instead.
    assert(*module != NULL);

    // Map the module.
    struct capref child_frame = {
        .cnode = cnode_module,
        .slot = (*module)->mrmod_slot,
    };
    err = paging_map_frame_attr(
        get_current_paging_state(),
        module_data,
        (*module)->mrmod_size,
        child_frame,
        VREGION_FLAGS_READ,
        NULL,
        NULL
    );
    // TODO: Return an error instead.
    assert((*module) != NULL);
    assert(IS_ELF(**(struct Elf64_Ehdr **) module_data));

    return SYS_ERR_OK;
}

static inline errval_t setup_cspace(struct capref dp_child, struct capref dp_frame, struct capref *cap_cnode_l1, struct capref *l0_table_child, struct cnoderef *taskcn)
{
    errval_t err;

    err = cnode_create_l1(cap_cnode_l1, NULL);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    struct cnoderef *cnode_l2_rootcn_slot_taskcn = taskcn;
    struct cnoderef cnode_l2_rootcn_slot_alloc_0;
    struct cnoderef cnode_l2_rootcn_slot_alloc_1;
    struct cnoderef cnode_l2_rootcn_slot_alloc_2;
    struct cnoderef cnode_l2_rootcn_slot_base_page_cn;
    struct cnoderef cnode_l2_rootcn_slot_pagecn;

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_TASKCN, cnode_l2_rootcn_slot_taskcn);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    err = fill_taskcn(dp_child, dp_frame, *cnode_l2_rootcn_slot_taskcn, *cap_cnode_l1);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_SLOT_ALLOC0, &cnode_l2_rootcn_slot_alloc_0);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_SLOT_ALLOC1, &cnode_l2_rootcn_slot_alloc_1);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_SLOT_ALLOC2, &cnode_l2_rootcn_slot_alloc_2);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_BASE_PAGE_CN, &cnode_l2_rootcn_slot_base_page_cn);
    // TODO: Return an error instead.
    assert(err_is_ok(err));
    struct capref cap_ram;
    struct capref cap_start = {
        .cnode = cnode_l2_rootcn_slot_base_page_cn,
        .slot = 0,
    };
    err = ram_alloc(&cap_ram, L2_CNODE_SLOTS * BASE_PAGE_SIZE);
    err = cap_retype(cap_start, cap_ram, 0, ObjType_RAM, BASE_PAGE_SIZE, L2_CNODE_SLOTS);

    err = cnode_create_foreign_l2(*cap_cnode_l1, ROOTCN_SLOT_PAGECN, &cnode_l2_rootcn_slot_pagecn);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    l0_table_child->cnode = cnode_l2_rootcn_slot_pagecn;
    l0_table_child->slot = 0;

    return SYS_ERR_OK;
}

static inline errval_t setup_vspace(struct capref l0_table_child, struct paging_state *paging_state_child)
{
    errval_t err;

    err = vnode_create(l0_table_child, ObjType_VNode_AARCH64_l0);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    err = paging_init_state_foreign(paging_state_child, VADDR_OFFSET, l0_table_child, get_default_slot_allocator());
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}

static inline errval_t parse_elf(struct mem_region *module, void *module_data, struct elf_allocator_state *as, genvaddr_t *retentry, void **got_section_addr)
{
    errval_t err;

    err = elf_load(
        EM_AARCH64,
        elf_allocator_func,
        as,
        (lvaddr_t) module_data,
        module->mrmod_size,
        retentry
    );
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    struct Elf64_Shdr *got;
    got = elf64_find_section_header_name((genvaddr_t) module_data, module->mrmod_size, ".got");
    // TODO: Return an error instead.
    assert(got != NULL);

    *got_section_addr = (void *) got->sh_addr;

    return SYS_ERR_OK;
}

static inline errval_t setup_arguments(struct paging_state *paging_state_child, struct capref args_frame_child, int argc, char *argv[])
{
    errval_t err;

    struct capref args_frame;
    size_t args_frame_size;
    void *args_page_parent;
    void *args_page_child;

    // TODO: Is BASE_PAGE_SIZE always large enough?
    err = frame_alloc(&args_frame, BASE_PAGE_SIZE, &args_frame_size);
    // TODO: Return an error instead.
    assert(err_is_ok(err));
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
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    err = paging_map_frame_attr(
        paging_state_child,
        &args_page_child,
        args_frame_size,
        args_frame,
        VREGION_FLAGS_READ_WRITE,
        NULL,
        NULL
    );
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    err = cap_copy(args_frame_child, args_frame);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    struct spawn_domain_params *params = (struct spawn_domain_params *) args_page_parent;

    // Everything that is not set explicitly should be zero.
    memset(args_page_parent, 0, args_frame_size);

    char *argv_data = args_page_parent + sizeof(struct spawn_domain_params);

    for (int i = 0; i < argc; i++) {
        strcpy(argv_data, argv[i]);
        int n = strlen(argv[i]) + 1;
        argv_data += n;
        params->argv[i] = argv_data - (char *)args_page_parent + args_page_child;
    }

    params->argc = argc;
    params->envp[0] = NULL;
    params->vspace_buf = NULL;
    params->vspace_buf_len = 0;
    params->tls_init_base = NULL;
    params->tls_init_len = 0;
    params->tls_total_len = 0;
    params->pagesize = 0;

    return SYS_ERR_OK;
}

static inline errval_t setup_dispatcher(struct paging_state *ps, char *name, struct capref dp_child, struct capref dp_frame, size_t dp_frame_bytes, void *got_section_addr, genvaddr_t entry_point_addr)
{
    errval_t err;

    // Map dispatcher into parent.
    void *dp_page_parent;
    err = paging_map_frame_attr(
        get_current_paging_state(),
        &dp_page_parent,
        dp_frame_bytes,
        dp_frame,
        VREGION_FLAGS_READ_WRITE,
        NULL,
        NULL
    );
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    // Map dispatcher into child.
    void *dp_page_child;
    err = paging_map_frame_attr(
        ps,
        &dp_page_child,
        dp_frame_bytes,
        dp_frame,
        VREGION_FLAGS_READ_WRITE,
        NULL,
        NULL
    );
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    dispatcher_handle_t handle_child = (dispatcher_handle_t) dp_page_parent;
    struct dispatcher_shared_generic *disp_child = get_dispatcher_shared_generic(handle_child);
    struct dispatcher_generic *disp_gen = get_dispatcher_generic(handle_child);
    arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area(handle_child);
    arch_registers_state_t *disabled_area = dispatcher_get_disabled_save_area(handle_child);

    disp_gen->core_id = my_core_id;
    disp_child->udisp = (lvaddr_t) dp_page_child;
    disp_child->disabled = 1;
    strncpy(disp_child->name, name, DISP_NAME_LEN);
    disabled_area->named.pc = (uint64_t) entry_point_addr;
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
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid) {
    errval_t err;

    // TODO: Fill the struct domainid_t argument.

    // Initialize the spawninfo struct.
    si->next = NULL;
    si->binary_name = argv[0];

    struct mem_region *module;
    void *module_data;

    err = load_module(si->binary_name, &module, &module_data);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    struct capref dp_child;
    struct capref dp_frame;
    struct capref cap_cnode_l1;
    struct capref l0_table_child;
    struct cnoderef taskcn_child;
    size_t dp_bytes;

    err = slot_alloc(&dp_child);
    // TODO: Return an error instead.
    assert(err_is_ok(err));
    err = dispatcher_create(dp_child);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    err = frame_alloc(&dp_frame, DISPATCHER_FRAME_SIZE, &dp_bytes);
    // TODO: Return an error instead.
    assert(err_is_ok(err));
    assert(dp_bytes >= DISPATCHER_FRAME_SIZE);

    err = setup_cspace(dp_child, dp_frame, &cap_cnode_l1, &l0_table_child, &taskcn_child);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    struct elf_allocator_state as;

    err = setup_vspace(l0_table_child, &as.paging_state_child);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    genvaddr_t entry_point_addr;
    void *got_section_addr;

    err = parse_elf(module, module_data, &as, &entry_point_addr, &got_section_addr);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    struct capref args_frame_child = {
        .cnode = taskcn_child,
        .slot = TASKCN_SLOT_ARGSPAGE,
    };
    err = setup_arguments(&as.paging_state_child, args_frame_child, argc, argv);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    err = setup_dispatcher(&as.paging_state_child, si->binary_name, dp_child, dp_frame, dp_bytes, got_section_addr, entry_point_addr);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    invoke_dispatcher(dp_child, cap_dispatcher, cap_cnode_l1, l0_table_child, dp_frame, true);

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
errval_t spawn_load_by_name(char *binary_name, struct spawninfo * si, domainid_t *pid) {
    // TODO: Return an error instead.
    assert(si != NULL);
    assert(pid != NULL);

    errval_t err;

    // Get the mem_region from the multiboot image.
    struct mem_region *module = multiboot_find_module(bi, binary_name);
    // TODO: Return an error instead.
    assert(module != NULL);

    const char *opts = multiboot_module_opts(module);
    // TODO: Return an error instead.
    assert(opts != NULL);

    int argc;
    char *buf;
    char **argv = make_argv(opts, &argc, &buf);
    // TODO: Return an error instead.
    assert(argv != NULL);

    err = spawn_load_argv(argc, argv, si, pid);
    // TODO: Return an error instead.
    assert(err_is_ok(err));

    return SYS_ERR_OK;
}
