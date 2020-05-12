#ifndef BF_AOS_BLOCK_DRIVER_H
#define BF_AOS_BLOCK_DRIVER_H

struct block_driver_state {
    struct capref sdhc;     ///< ObjType_DevFrame capability to SDHC
    struct capref frame;    ///< Mapped frame used for read/write_vaddr
    lvaddr_t sdhc_vaddr;    ///< Virtual address of mapped SDHC (is passed to sdhc_init)
    lvaddr_t write_vaddr;   ///< Virtual address of memory region that is used to write block to SDHC
    lvaddr_t read_vaddr;    ///< Virtual address of memory region that is used to read block from SDHC
    lpaddr_t write_paddr;   ///< write_vaddr maps to this physical address
    lpaddr_t read_paddr;    ///< read_vaddr maps to this physical address
};

errval_t block_driver_add_client(struct aos_rpc *rpc, coreid_t mpid);
errval_t block_driver_serve_next(void);
errval_t block_driver_init(void);

#endif //BF_AOS_BLOCK_DRIVER_H
