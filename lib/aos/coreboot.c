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



errval_t coreboot(coreid_t mpid,
        const char *boot_driver,
        const char *cpu_driver,
        const char *init,
        struct frame_identity urpc_frame_id)
{
    errval_t err;

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
    err = cap_retype(kcb, ram_cap, 0, ObjType_KernelControlBlock, OBJSIZE_KCB, 1);
    if (err_is_fail(err)) {
        goto err_clean_up_ram_cap;
    }

    // - Get and load the CPU binary.
    // we might be able to reuse code from spawn.c by generalizing a bit (see load_module)
    struct mem_region *cpu_module = multiboot_find_module(bi, "cpu_imx8x");
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
            cpu_module_addr,
            cpu_module->mrmod_size,
            cpu_frame,
            VREGION_FLAGS_READ,
            NULL,
            NULL
    );
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // get entrypoint
    uintptr_t sindex = 0;
    struct Elf64_Sym *sym = elf64_find_symbol_by_name((genvaddr_t) cpu_module_addr,
                                                      cpu_module->mrmod_size,
                                                      "arch_init",
                                                      0,
                                                      STT_FUNC,
                                                      &sindex);
    // get physical base addr
    struct frame_identity cpu_frame_identiy;
    err = frame_identify(cpu_frame, &cpu_frame_identiy);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    struct mem_info mem = {
            .size = cpu_module->mrmod_size,
            .buf = cpu_module_addr,
            .phys_base = cpu_frame_identiy.base,
    };

    genvaddr_t reloc_entry_point;
    err = load_elf_binary((genvaddr_t) cpu_module_addr, &mem,
                          (genvaddr_t) sym->st_value, &reloc_entry_point);
    if (err_is_fail(err)) {
        goto err_clean_up_kcb_cap;
    }

    // - Get and load the boot driver binary.

    // - Relocate the boot and CPU driver. The boot driver runs with a 1:1
    //   VA->PA mapping. The CPU driver is expected to be loaded at the
    //   high virtual address space, at offset ARMV8_KERNEL_OFFSET.
    // - Allocate a page for the core data struct
    // - Allocate stack memory for the new cpu driver (at least 16 pages)
    // - Fill in the core data struct, for a description, see the definition
    //   in include/target/aarch64/barrelfish_kpi/arm_core_data.h
    // - Find the CPU driver entry point. Look for the symbol "arch_init". Put
    //   the address in the core data struct.
    // - Find the boot driver entry point. Look for the symbol "boot_entry_psci"
    // - Flush the cache.
    // - Call the invoke_monitor_spawn_core with the entry point
    //   of the boot driver and pass the (physical, of course) address of the
    //   boot struct as argument.

    return SYS_ERR_OK;  // only remove resources in case of error
err_clean_up_kcb_cap:
    cap_destroy(kcb);
err_clean_up_ram_cap:
    cap_destroy(ram_cap);
    return err;
}
