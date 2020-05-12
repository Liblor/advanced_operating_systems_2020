#ifndef BF_AOS_BLOCK_DRIVER_H
#define BF_AOS_BLOCK_DRIVER_H

struct block_driver_state {
    struct capref frame;
    lvaddr_t write_vaddr;
    lvaddr_t read_vaddr;
    lpaddr_t write_paddr;
    lpaddr_t read_paddr;
};

errval_t block_driver_add_client(struct aos_rpc *rpc, coreid_t mpid);
errval_t block_driver_serve_next(void);
errval_t block_driver_init(genvaddr_t vaddr_base);

#endif //BF_AOS_BLOCK_DRIVER_H
