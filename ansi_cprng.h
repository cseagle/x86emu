#ifndef __ANSI_CPRNG_H
#define __ANSI_CPRNG_H

#define CPRNG_BLOCK_SIZE 16
#define CPRNG_VALID 0
#define CPRNG_INVALID 1

struct cprng_ctx {
   unsigned int data_idx;
   unsigned int flags;
   unsigned char I[CPRNG_BLOCK_SIZE];
   unsigned char V[CPRNG_BLOCK_SIZE];
   unsigned char K[CPRNG_BLOCK_SIZE];
   unsigned char DT[CPRNG_BLOCK_SIZE];
   unsigned char data[CPRNG_BLOCK_SIZE];
   unsigned char last_data[CPRNG_BLOCK_SIZE];   
};

int ctx_init(cprng_ctx *ctx, unsigned char *seed, unsigned int slen);
int get_bytes(cprng_ctx *ctx, unsigned char *buf, unsigned int nbytes);
#define is_valid(ctx) (ctx->flags == CPRNG_VALID)

#endif

