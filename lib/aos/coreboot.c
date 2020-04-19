#include <aos/aos.h>
#include <aos/coreboot.h>
#include <spawn/multiboot.h>
#include <elf/elf.h>
#include <string.h>
#include <barrelfish_kpi/arm_core_data.h>
#include <aos/kernel_cap_invocations.h>
#include <aos/cache.h>
#include <init.h>

#define ARMv8_KERNEL_OFFSET 0xffff000000000000

extern struct bootinfo *bi;
extern void boot_entry_psci(void);

struct mem_info {
    size_t                size;      // Size in bytes of the memory region
    void                  *buf;      // Address where the region is currently mapped
    lpaddr_t              phys_base; // Physical base address
};

/**
 * Load a ELF image into memory.
 *
 * binary:            Valid pointer to ELF image in current address space
 * mem:               Where the ELF will be loaded
 * entry_point:       Virtual address of the entry point
 * reloc_entry_point: Return the loaded, physical address of the entry_point
 */
__attribute__((__used__))
static errval_t load_elf_binary(genvaddr_t binary, const struct mem_info *mem,
                         genvaddr_t entry_point, genvaddr_t *reloc_entry_point)

{

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    /* Load the CPU driver from its ELF image. */
    bool found_entry_point= 0;
    bool loaded = 0;

    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    for(size_t i= 0; i < ehdr->e_phnum; i++) {
        if(phdr[i].p_type != PT_LOAD) {
            DEBUG_PRINTF("Segment %d load address 0x% "PRIx64 ", file size %" PRIu64
                  ", memory size 0x%" PRIx64 " SKIP\n", i, phdr[i].p_vaddr,
                  phdr[i].p_filesz, phdr[i].p_memsz);
            continue;
        }

        DEBUG_PRINTF("Segment %d load address 0x% "PRIx64 ", file size %" PRIu64
              ", memory size 0x%" PRIx64 " LOAD\n", i, phdr[i].p_vaddr,
              phdr[i].p_filesz, phdr[i].p_memsz);


        if (loaded) {
            USER_PANIC("Expected one load able segment!\n");
        }
        loaded = 1;

        void *dest = mem->buf;
        lpaddr_t dest_phys = mem->phys_base;

        assert(phdr[i].p_offset + phdr[i].p_memsz <= mem->size);

        /* copy loadable part */
        memcpy(dest, (void *)(binary + phdr[i].p_offset), phdr[i].p_filesz);

        /* zero out BSS section */
        memset(dest + phdr[i].p_filesz, 0, phdr[i].p_memsz - phdr[i].p_filesz);

        if (!found_entry_point) {
            if(entry_point >= phdr[i].p_vaddr
                 && entry_point - phdr[i].p_vaddr < phdr[i].p_memsz) {
               *reloc_entry_point= (dest_phys + (entry_point - phdr[i].p_vaddr));
               found_entry_point= 1;
            }
        }
    }

    if (!found_entry_point) {
        USER_PANIC("No entry point loaded\n");
    }

    return SYS_ERR_OK;
}

/**
 * Relocate an already loaded ELF image.
 *
 * binary:            Valid pointer to ELF image in current address space
 * mem:               Where the ELF is loaded
 * kernel_:       Virtual address of the entry point
 * reloc_entry_point: Return the loaded, physical address of the entry_point
 */
__attribute__((__used__))
static errval_t
relocate_elf(genvaddr_t binary, struct mem_info *mem, lvaddr_t load_offset)
{
    DEBUG_PRINTF("Relocating image.\n");

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    size_t shnum  = ehdr->e_shnum;
    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    struct Elf64_Shdr *shead = (struct Elf64_Shdr *)(binary + (uintptr_t)ehdr->e_shoff);

    /* Search for relocaton sections. */
    for(size_t i= 0; i < shnum; i++) {

        struct Elf64_Shdr *shdr=  &shead[i];
        if(shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA) {
            if(shdr->sh_info != 0) {
                DEBUG_PRINTF("I expected global relocations, but got"
                              " section-specific ones.\n");
                return ELF_ERR_HEADER;
            }


            uint64_t segment_elf_base= phdr[0].p_vaddr;
            uint64_t segment_load_base=mem->phys_base;
            uint64_t segment_delta= segment_load_base - segment_elf_base;
            uint64_t segment_vdelta= (uintptr_t)mem->buf - segment_elf_base;

            size_t rsize;
            if(shdr->sh_type == SHT_REL){
                rsize= sizeof(struct Elf64_Rel);
            } else {
                rsize= sizeof(struct Elf64_Rela);
            }

            assert(rsize == shdr->sh_entsize);
            size_t nrel= shdr->sh_size / rsize;

            void * reldata = (void*)(binary + shdr->sh_offset);

            /* Iterate through the relocations. */
            for(size_t ii= 0; ii < nrel; ii++) {
                void *reladdr= reldata + ii *rsize;

                switch(shdr->sh_type) {
                    case SHT_REL:
                        DEBUG_PRINTF("SHT_REL unimplemented.\n");
                        return ELF_ERR_PROGHDR;
                    case SHT_RELA:
                    {
                        struct Elf64_Rela *rel= reladdr;

                        uint64_t offset= rel->r_offset;
                        uint64_t sym= ELF64_R_SYM(rel->r_info);
                        uint64_t type= ELF64_R_TYPE(rel->r_info);
                        uint64_t addend= rel->r_addend;

                        uint64_t *rel_target= (void *)offset + segment_vdelta;

                        switch(type) {
                            case R_AARCH64_RELATIVE:
                                if(sym != 0) {
                                    DEBUG_PRINTF("Relocation references a"
                                                 " dynamic symbol, which is"
                                                 " unsupported.\n");
                                    return ELF_ERR_PROGHDR;
                                }

                                /* Delta(S) + A */
                                *rel_target= addend + segment_delta + load_offset;
                                break;

                            default:
                                DEBUG_PRINTF("Unsupported relocation type %d\n",
                                             type);
                                return ELF_ERR_PROGHDR;
                        }
                    }
                    break;
                    default:
                        DEBUG_PRINTF("Unexpected type\n");
                        break;

                }
            }
        }
    }

    return SYS_ERR_OK;
}

/* utility, returns frame_identity information for cap */
static inline errval_t frame_base_size(
        struct capref frame,
        genpaddr_t *ret_base,
        gensize_t *ret_size
) {
    struct frame_identity frame_identity;
    errval_t err = frame_identify(frame, &frame_identity);
    if (err_is_fail(err)) {
        return err;
    }

    *ret_base = frame_identity.base;
    *ret_size = frame_identity.bytes;
    return SYS_ERR_OK;
}

static inline errval_t alloc_frame_and_map(
        size_t size,
        void **buf,
        struct capref *ret_frame,
        size_t *ret_size
) {
    errval_t err;
    err = frame_alloc(ret_frame, size, ret_size);
    if (err_is_fail(err)) {
        return err;
    }

    if (*ret_size < size) {
        cap_destroy(*ret_frame);
        return LIB_ERR_FRAME_ALLOC_SIZE;
    }

    err = paging_map_frame_attr(
            get_current_paging_state(),
            buf,
            *ret_size,
            *ret_frame,
            VREGION_FLAGS_READ_WRITE,
            0,
            0
    );
    if (err_is_fail(err)) {
        cap_destroy(*ret_frame);
        return err;
    }
    return err;
}


static errval_t create_new_kcb(
        struct capref *kcb
) {
    errval_t err;
    struct capref ram_cap;
    err = ram_alloc_aligned(&ram_cap, OBJSIZE_KCB, 4*BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err;
    }

    err = slot_alloc(kcb);
    if (err_is_fail(err)) {
        goto err_clean_up_ram_cap;
    }

    err = cap_retype(*kcb, ram_cap, 0,ObjType_KernelControlBlock,OBJSIZE_KCB,1);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    return SYS_ERR_OK;
err_clean_up_kcb_cap:
    cap_destroy(*kcb);
err_clean_up_ram_cap:
    cap_destroy(ram_cap);
    return err;
}

static errval_t load_and_relocate_binary(
        const char *module_name,
        const char *entrypoint_name,
        lvaddr_t reloc_offset,
        struct mem_region **ret_module,
        genvaddr_t *ret_reloc_entry_point
) {
    errval_t err;
    *ret_module = multiboot_find_module(bi, module_name);
    if (module_name == NULL) {
        return SPAWN_ERR_FIND_MODULE;
    }
    struct capref cpu_frame = {
            .cnode = cnode_module,
            .slot = (*ret_module)->mrmod_slot,
    };
    void *module_addr = NULL;
    err = paging_map_frame_attr(
            get_current_paging_state(),
            &module_addr,
            (*ret_module)->mrmod_size,
            cpu_frame,
            VREGION_FLAGS_READ_WRITE,
            NULL,
            NULL
    );
    if (err_is_fail(err)) {
        return err;
    }

    struct capref mem_frame;
    size_t mem_size;
    err = frame_alloc(&mem_frame, (*ret_module)->mrmod_size, &mem_size);
    if (err_is_fail(err)) {
        return err;
    }
    void *mem_buf;
    err = paging_map_frame_attr(
            get_current_paging_state(),
            &mem_buf,
            mem_size,
            mem_frame,
            VREGION_FLAGS_READ_WRITE,
            NULL,
            NULL
    );
    if (err_is_fail(err)) {
        return err;
    }

    struct mem_info module_mem;
    module_mem.buf = mem_buf;
    err = frame_base_size(mem_frame, &module_mem.phys_base, &module_mem.size);
    if (err_is_fail(err)) {
        return err;
    }

    // get entry point
    uintptr_t sindex = 0;
    struct Elf64_Sym *entrypoint = elf64_find_symbol_by_name(
            (genvaddr_t) module_addr,
            (*ret_module)->mrmod_size,
            entrypoint_name,
            0,
            STT_FUNC,
            &sindex
    );
    err = load_elf_binary(
            (genvaddr_t) module_addr,
            &module_mem,
            (genvaddr_t) entrypoint->st_value,
            ret_reloc_entry_point
    );
    if (err_is_fail(err)) {
        return err;
    }
    *ret_reloc_entry_point += reloc_offset;

    // Relocate module
    err = relocate_elf(
            (genvaddr_t) module_addr,
            &module_mem,
            reloc_offset
    );
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}


static errval_t load_init_binary_in_curr_vspace(
        const char *binary_name,
        struct armv8_coredata_memreg *ret_binary_memreg,
        void **ret_init_binary_loaded
){
errval_t  err;

    struct mem_region *init_module = multiboot_find_module(bi, binary_name);
    if (init_module == NULL) {
        err = SPAWN_ERR_FIND_MODULE;
        goto error_handling;
    }
    struct capref init_frame = {
            .cnode = cnode_module,
            .slot = init_module->mrmod_slot,
    };

    err = frame_base_size(
            init_frame,
            &ret_binary_memreg->base,
            &ret_binary_memreg->length
    );
    if (err_is_fail(err)) {
        goto error_handling;
    }

    // we need to map init_module into vaddr space for elf_virtual_size in
    // CPU driver's allocations
    err = paging_map_frame_attr(
            get_current_paging_state(),
            ret_init_binary_loaded,
            ret_binary_memreg->length,
            init_frame,
            VREGION_FLAGS_READ_WRITE,
            0,
            0
    );
    if (err_is_fail(err)) {
        goto error_handling;
    }

    return SYS_ERR_OK;

    error_handling:
    return err;
}

static errval_t initialize_core_data(
        struct armv8_core_data *core_data,
        struct capref stack_frame,
        const genvaddr_t arch_init_reloc,
        struct mem_region *cpu_module,
        coreid_t mpid,
        struct capref kcb,
        void *init_monitor_module_vaddr,                    //< ref to init monitor mapped in current vspace
        struct armv8_coredata_memreg *init_monitor_memreg,  //< ref to init monitor frame identity
        struct frame_identity urpc_frame_id
) {
    errval_t err;

    // CPU driver
    // iMX8 is using PSCI
    core_data->boot_magic = ARMV8_BOOTMAGIC_PSCI;
    {
        genpaddr_t cpu_driver_stack_paddr;
        gensize_t cpu_driver_stack_size;
        err = frame_base_size(stack_frame, &cpu_driver_stack_paddr, &cpu_driver_stack_size);
        if (err_is_fail(err)) {
            return err;
        }
        // stack grows downwards
        // XXX: stack needs to be aligned to 8 bytes acc. to moodle
        core_data->cpu_driver_stack = ROUND_DOWN(cpu_driver_stack_paddr + cpu_driver_stack_size, 8);
        core_data->cpu_driver_stack_limit = cpu_driver_stack_paddr;

        core_data->cpu_driver_entry = arch_init_reloc;
    }

    // kernel command line args
    {
        const size_t cmd_len = sizeof(core_data->cpu_driver_cmdline);
        memset(core_data->cpu_driver_cmdline, 0, cmd_len);
        const char *opts = multiboot_module_opts(cpu_module);
        if (opts != NULL) {
            strlcpy(core_data->cpu_driver_cmdline, opts, cmd_len);
        } else {
            debug_printf("no command line args are given to cpu driver");
        }
    }

    // init monitor
    core_data->monitor_binary.base = init_monitor_memreg->base;
    core_data->monitor_binary.length = init_monitor_memreg->length;

    // Memory for CPU driver's allocations
    {
        size_t size = ARMV8_CORE_DATA_PAGES * BASE_PAGE_SIZE
                      + elf_virtual_size((lvaddr_t) init_monitor_module_vaddr);

        struct capref cpu_driver_alloc_frame;
        err = frame_alloc(
                &cpu_driver_alloc_frame,
                size,
                &size);

        if (err_is_fail(err)) {
            goto errror_handling;
        }

        // get physical addr
        struct frame_identity physical_id;
        err = frame_identify(
                cpu_driver_alloc_frame,
                &physical_id);

        if (err_is_fail(err)) {
            goto errror_handling;
        }
        core_data->memory.base = physical_id.base;
        core_data->memory.length = physical_id.bytes;
    }

    // URPC Frame
    core_data->urpc_frame.base = urpc_frame_id.base;
    core_data->urpc_frame.length = urpc_frame_id.bytes;

    // KCB
    {
        struct frame_identity kcb_frame_identity;
        err = invoke_kcb_identify(kcb, &kcb_frame_identity);
        if (err_is_fail(err)) {
            goto errror_handling;
        }
        core_data->kcb = kcb_frame_identity.base;
    }

    // Logical core id of the invoking core.
    core_data->src_core_id = disp_get_core_id();

    // Physical core id of the invoking core
    core_data->src_arch_id = disp_get_core_id();

    // Logical core id of the started core
    core_data->dst_core_id = mpid;

    //  Physical core id of the started core
    core_data->dst_arch_id = mpid;

    return SYS_ERR_OK;

    errror_handling:
    return err;
}


errval_t coreboot(coreid_t mpid,
        const char *boot_driver_name,
        const char *cpu_driver_name,
        const char *init_binary_name,
        struct frame_identity urpc_frame_id)
{
    errval_t err;

    // TODO: free all slots created by frame alloc

    // - Get a new KCB by retyping a RAM cap to ObjType_KernelControlBlock.
    struct capref kcb;
    err = create_new_kcb(&kcb);
    if (err_is_fail(err)) {
        return err;
    }

    // - Load and reloc the CPU driver binary.
    struct mem_region *cpu_driver_module;
    genvaddr_t cpu_driver_reloc;
    err = load_and_relocate_binary(
            cpu_driver_name,
            "arch_init",
            ARMv8_KERNEL_OFFSET,
            &cpu_driver_module,
            &cpu_driver_reloc
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // - Load and reloc the boot driver binary.
    struct mem_region *boot_driver_module;
    genvaddr_t boot_driver_reloc;
    err = load_and_relocate_binary(
            boot_driver_name,
            "boot_entry_psci",
            0,
            &boot_driver_module,
            &boot_driver_reloc
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // - Allocate stack memory for the new cpu driver (at least 16 pages)
    struct capref cpu_driver_stack_cap;
    void *cpu_driver_stack;
    size_t stack_size;
    err = alloc_frame_and_map(
            16 * BASE_PAGE_SIZE,
            (void **) &cpu_driver_stack,
            &cpu_driver_stack_cap,
            &stack_size
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // - Load init monitor binary into current vspace
    struct armv8_coredata_memreg init_monitor_memreg;      // reference to phyaddr
    void *init_monitor_vaddr;                              // ref. to vaddr

    err = load_init_binary_in_curr_vspace(
            init_binary_name,
            &init_monitor_memreg,
            &init_monitor_vaddr);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // - Allocate a page for the core data struct
    struct armv8_core_data *core_data = NULL;
    struct capref core_data_frame;
    size_t core_data_size;
    err = alloc_frame_and_map(
            BASE_PAGE_SIZE,
            (void **) &core_data,
            &core_data_frame,
            &core_data_size
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // - Setup core_data structure for boot
    err = initialize_core_data(
            core_data,
            cpu_driver_stack_cap,
            cpu_driver_reloc,
            cpu_driver_module,
            mpid,
            kcb,
            init_monitor_vaddr,
            &init_monitor_memreg,
            urpc_frame_id);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // - Flush the cache.
    arm64_dcache_wb_range((vm_offset_t) core_data, core_data_size);
    arm64_idcache_wbinv_range((vm_offset_t) core_data, core_data_size);
    arm64_dcache_wb_range((vm_offset_t) cpu_driver_stack, stack_size);
    arm64_idcache_wbinv_range((vm_offset_t) cpu_driver_stack, stack_size);


    // - Call the invoke_monitor_spawn_core with the entry point
    //   of the boot driver and pass the (physical, of course) address of the
    //   boot struct as argument.
    struct frame_identity core_data_frame_identity;
    err = frame_identify(core_data_frame, &core_data_frame_identity);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    err = invoke_monitor_spawn_core(
            mpid,
            CPU_ARM8,
            boot_driver_reloc,
            core_data_frame_identity.base,
            0
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    return SYS_ERR_OK;  // only remove resources in case of error
err_clean_up_kcb_cap:
    cap_destroy(kcb);
    return err;
}
