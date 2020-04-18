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

#define err_is_fail(err) ((err_is_fail(err) ? (HERE, DEBUG_ERR(err, "error occured"), true) : (HERE, false)))

errval_t coreboot(coreid_t mpid,
        const char *boot_driver,
        const char *cpu_driver,
        const char *init,
        struct frame_identity urpc_frame_id)
{
    errval_t err;

    // TODO: free all slots created by frame alloc

    // Implement me!
    // - Get a new KCB by retyping a RAM cap to ObjType_KernelControlBlock.
    //   Note that it should at least OBJSIZE_KCB, and it should also be aligned
    //   to a multiple of 16k.
    struct capref ram_cap;
    err = ram_alloc_aligned(&ram_cap, OBJSIZE_KCB, 4*BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err;
    }

    struct capref kcb;
    err = slot_alloc(&kcb);
    if (err_is_fail(err)) {
        goto err_clean_up_ram_cap;
    }

    err = cap_retype(
            kcb,
            ram_cap,
            0,
            ObjType_KernelControlBlock,
            OBJSIZE_KCB,
            1);

    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // - Get and load the CPU binary.
    // we might be able to reuse code from spawn.c by generalizing a bit (see load_module)
    struct mem_region *cpu_module = multiboot_find_module(bi, cpu_driver);
    if (cpu_module == NULL) {
        err = SPAWN_ERR_FIND_MODULE;
        goto err_clean_up_kcb_cap;
    }
    struct capref cpu_frame = {
            .cnode = cnode_module,
            .slot = cpu_module->mrmod_slot,
    };
    void *cpu_module_addr = NULL;
    err = paging_map_frame_attr(
            get_current_paging_state(),
            &cpu_module_addr,
            cpu_module->mrmod_size,
            cpu_frame,
            VREGION_FLAGS_READ_WRITE,
            NULL,
            NULL
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // get entrypoint of arch_init
    uintptr_t sindex = 0;
    struct Elf64_Sym *sym_arch_init = elf64_find_symbol_by_name((genvaddr_t) cpu_module_addr,
                                                                cpu_module->mrmod_size,
                                                                "arch_init",
                                                                0,
                                                                STT_FUNC,
                                                                &sindex);
    struct mem_info cpu_module_mem;
    struct capref mem_frame;
    size_t mem_size;
    err = frame_alloc(&mem_frame, cpu_module->mrmod_size, &mem_size);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    struct frame_identity mem_frame_identiy;
    err = frame_identify(mem_frame, &mem_frame_identiy);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
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
        goto err_clean_up_kcb_cap;
    }

    cpu_module_mem.size = cpu_module->mrmod_size;
    cpu_module_mem.buf = mem_buf;
    cpu_module_mem.phys_base = mem_frame_identiy.base;

    genvaddr_t reloc_entry_point;
    err = load_elf_binary((genvaddr_t) cpu_module_addr, &cpu_module_mem,
                          (genvaddr_t) sym_arch_init->st_value, &reloc_entry_point);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // Relocate cpu driver
    // The CPU driver is expected to be loaded at the
    // high virtual address space, at offset ARMV8_KERNEL_OFFSET
    err = relocate_elf(
            (genvaddr_t) cpu_module_addr,
            &cpu_module_mem,
            ARMv8_KERNEL_OFFSET);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }
    const lvaddr_t arch_init_reloc = reloc_entry_point + ARMv8_KERNEL_OFFSET;

    // - Get and load the boot driver binary.
    struct mem_region *boot_module = multiboot_find_module(bi, boot_driver);
    if (boot_module == NULL) {
        err = SPAWN_ERR_FIND_MODULE;
        goto err_clean_up_kcb_cap;
    }
    struct capref boot_frame = {
            .cnode = cnode_module,
            .slot = boot_module->mrmod_slot,
    };
    void *boot_module_addr = NULL;
    err = paging_map_frame_attr(
            get_current_paging_state(),
            &boot_module_addr,
            boot_module->mrmod_size,
            boot_frame,
            VREGION_FLAGS_READ_WRITE,
            NULL,
            NULL
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // get entrypoint
    sindex = 0;
    sym_arch_init = elf64_find_symbol_by_name((genvaddr_t) boot_module_addr,
                                              boot_module->mrmod_size,
                                              "boot_entry_psci",
                                              0,
                                              STT_FUNC,
                                              &sindex);
    // get physical base addr
    struct frame_identity boot_frame_identiy;
    err = frame_identify(boot_frame, &boot_frame_identiy);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    struct capref mem_boot_frame;
    size_t mem_boot_size;
    err = frame_alloc(&mem_boot_frame, boot_module->mrmod_size, &mem_boot_size);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    struct frame_identity mem_boot_frame_identiy;
    err = frame_identify(mem_boot_frame, &mem_boot_frame_identiy);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }
    void *mem_boot_buf;
    err = paging_map_frame_attr(
            get_current_paging_state(),
            &mem_boot_buf,
            mem_boot_size,
            mem_boot_frame,
            VREGION_FLAGS_READ_WRITE,
            NULL,
            NULL
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    struct mem_info mem_boot = (struct mem_info) {
            .size = boot_module->mrmod_size,
            .buf = mem_boot_buf,
            .phys_base = mem_boot_frame_identiy.base,
    };

    genvaddr_t boot_reloc_entry_point;
    err = load_elf_binary((genvaddr_t) boot_module_addr, &mem_boot,
                          (genvaddr_t) sym_arch_init->st_value, &boot_reloc_entry_point);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // Relocate the boot driver
    // The boot driver runs with a 1:1  VA->PA mapping.
    err = relocate_elf(
            (genvaddr_t) boot_module_addr,
            &cpu_module_mem,
            0);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }
    // TODO: store this somewhere, 1:1, use boot_reloc_entry_point directly
    __unused const lvaddr_t boot_entry_psci_reloc = boot_reloc_entry_point;

    // - Allocate a page for the core data struct
    struct capref core_data_frame;
    size_t core_data_size;
    err = frame_alloc(&core_data_frame, BASE_PAGE_SIZE, &core_data_size);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }
    struct armv8_core_data *core_data = NULL;
    err = paging_map_frame_attr(
            get_current_paging_state(),
            (void **)&core_data,
            core_data_size,
            core_data_frame,
            VREGION_FLAGS_READ_WRITE,
            0,
            0
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // - Allocate stack memory for the new cpu driver (at least 16 pages)
    struct capref stack_frame;
    size_t stack_size;
    err = frame_alloc(&stack_frame, 16*BASE_PAGE_SIZE, &stack_size);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }
    void *stack;
    err = paging_map_frame_attr(
            get_current_paging_state(),
            &stack,
            stack_size,
            stack_frame,
            VREGION_FLAGS_READ_WRITE,
            0,
            0
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // iMX8 is using PSCI
    core_data->boot_magic = ARMV8_BOOTMAGIC_PSCI;
    {
        // get physical addr of cpu_driver_stack
        struct frame_identity cpu_driver_stack_id;
        err = frame_identify(
                stack_frame,
                &cpu_driver_stack_id);

        if (err_is_fail(err)) {
            goto err_clean_up_kcb_cap;
        }
        // stack grows downwards
        // XXX: stack needs to be aligned to 8 bytes acc. to moodle
        core_data->cpu_driver_stack = ROUND_DOWN(cpu_driver_stack_id.base + cpu_driver_stack_id.bytes, 8);
        core_data->cpu_driver_stack_limit = cpu_driver_stack_id.base;
    }

    core_data->cpu_driver_entry = arch_init_reloc;

    // kernel command line args
    const size_t cmd_len = sizeof(core_data->cpu_driver_cmdline);
    memset(core_data->cpu_driver_cmdline, 0, cmd_len);
    const char *opts = multiboot_module_opts(cpu_module);
    if (opts != NULL) {
        strlcpy(core_data->cpu_driver_cmdline, opts, cmd_len);
    }

    // init monitor
    void *init_monitor_module_vaddr = NULL;
    {
        struct mem_region *init_module = multiboot_find_module(bi, init);
        if (init_module == NULL) {
            err = SPAWN_ERR_FIND_MODULE;
            goto err_clean_up_kcb_cap;
        }
        struct capref init_frame = {
                .cnode = cnode_module,
                .slot = init_module->mrmod_slot,
        };

        struct frame_identity init_frame_identity;
        err = frame_identify(init_frame, &init_frame_identity);
        if (err_is_fail(err)) {
            goto err_clean_up_kcb_cap;
        }

        core_data->monitor_binary.base = init_frame_identity.base;
        core_data->monitor_binary.length = init_frame_identity.bytes;

        // we need to map init_module into vaddr space for elf_virtual_size in
        // CPU driver's allocations
        err = paging_map_frame_attr(
                get_current_paging_state(),
                &init_monitor_module_vaddr,
                init_frame_identity.bytes,
                init_frame,
                VREGION_FLAGS_READ_WRITE,
                0,
                0
        );
        if (err_is_fail(err)) {
            goto err_clean_up_kcb_cap;
        }
    }

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
            goto err_clean_up_kcb_cap;
        }

        // get physical addr
        struct frame_identity physical_id;
        err = frame_identify(
                cpu_driver_alloc_frame,
                &physical_id);

        if (err_is_fail(err)) {
            goto err_clean_up_kcb_cap;
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
        //err = frame_identify(kcb, &kcb_frame_identity);
        err = invoke_kcb_identify(kcb, &kcb_frame_identity);
        if (err_is_fail(err)) {
            goto err_clean_up_kcb_cap;
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
    core_data->dst_arch_id = 1;

    // - Fill in the core data struct, for a description, see the definition
    //   in include/target/aarch64/barrelfish_kpi/arm_core_data.h
    // - Find the CPU driver entry point. Look for the symbol "arch_init". Put
    //   the address in the core data struct.
    // - Find the boot driver entry point. Look for the symbol "boot_entry_psci"
    // - Flush the cache.
    arm64_dcache_wb_range((vm_offset_t) core_data, core_data_size);
    arm64_idcache_wbinv_range((vm_offset_t) core_data, core_data_size);
    arm64_dcache_wb_range((vm_offset_t) stack, stack_size);
    arm64_idcache_wbinv_range((vm_offset_t) stack, stack_size);
    arm64_dcache_wb_range((vm_offset_t) mem_buf, mem_size);
    arm64_idcache_wbinv_range((vm_offset_t) mem_buf, mem_size);
    arm64_dcache_wb_range((vm_offset_t) mem_boot_buf, mem_boot_size);
    arm64_idcache_wbinv_range((vm_offset_t) mem_boot_buf, mem_boot_size);



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
            boot_entry_psci_reloc,
            core_data_frame_identity.base,
            0
    );

    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    return SYS_ERR_OK;  // only remove resources in case of error
err_clean_up_kcb_cap:
    cap_destroy(kcb);
err_clean_up_ram_cap:
    cap_destroy(ram_cap);
    return err;
}
