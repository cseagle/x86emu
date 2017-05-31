#include <string.h>
#include <stdint.h>

#include "ansi_cprng.h"
#include "aes.h"  

//aes 128 based rng
//see http://csrc.nist.gov/groups/STM/cavp/documents/rng/931rngext.pdf
//test vectors http://csrc.nist.gov/groups/STM/cavp/documents/rng/RNGVS.pdf B.2.9 and B.2.10

static void xor_16(uint8_t *v1, uint8_t *v2, uint8_t *vout) {
   uint32_t *u1 = (uint32_t*)v1;
   uint32_t *u2 = (uint32_t*)v2;
   uint32_t *v = (uint32_t*)vout;
   v[0] = u1[0] ^ u2[0];
   v[1] = u1[1] ^ u2[1];
   v[2] = u1[2] ^ u2[2];
   v[3] = u1[3] ^ u2[3];
}

/*
 * seed should be 48 bytes in 3x16 byte blocks
 *    V : K : DT
 */
int ctx_init(cprng_ctx *ctx, uint8_t *seed, uint32_t slen) {
   ctx->flags = CPRNG_INVALID;
   if (slen != (3 * CPRNG_BLOCK_SIZE)) {
      return 0;
   }
   
   if (memcmp(seed, seed + CPRNG_BLOCK_SIZE, CPRNG_BLOCK_SIZE) == 0) {
      return 0;
   }
   
   memcpy(ctx->V, seed, CPRNG_BLOCK_SIZE);
   memcpy(ctx->K, seed + CPRNG_BLOCK_SIZE, CPRNG_BLOCK_SIZE);
   memcpy(ctx->DT, seed + (2 * CPRNG_BLOCK_SIZE), CPRNG_BLOCK_SIZE);
   
   memset(ctx->data, 0, CPRNG_BLOCK_SIZE);
   memset(ctx->last_data, 0, CPRNG_BLOCK_SIZE);
   ctx->data_idx = CPRNG_BLOCK_SIZE;
   
   ctx->flags = CPRNG_VALID;
   
   return 1;
}

/*
 * Returns 16 bytes of random data per call
 * returns 0 if generation succeeded, -1 if something went wrong
 */
static int _get_more_bytes(cprng_ctx *ctx) {
   uint8_t tmp[CPRNG_BLOCK_SIZE];

   /*
    * Start by encrypting the counter value
    * This gives us an intermediate value I
    */
   memcpy(tmp, ctx->DT, CPRNG_BLOCK_SIZE);
   AES128_ECB_encrypt(tmp, ctx->K, ctx->I);

   /*
    * Next xor I with our secret vector V
    * encrypt that result to obtain our
    * pseudo random data which we output
    */
   xor_16(ctx->I, ctx->V, tmp);
   AES128_ECB_encrypt(tmp, ctx->K, ctx->data);

   /*
    * First check that we didn't produce the same
    * random data that we did last time around
    */
   if (!memcmp(ctx->data, ctx->last_data, CPRNG_BLOCK_SIZE)) {
      ctx->flags = CPRNG_INVALID;
      return -1;
   }
   memcpy(ctx->last_data, ctx->data, CPRNG_BLOCK_SIZE);

   /*
    * Lastly xor the random data with I
    * and encrypt that to obtain a new secret vector V
    */
   xor_16(ctx->data, ctx->I, tmp);
   AES128_ECB_encrypt(tmp, ctx->K, ctx->V);

   /*
    * DT++
    * DT is a big-endian 128 bit integer
    * this is ripple addition across 16 bytes
    */
   int i = CPRNG_BLOCK_SIZE;
   do {
      ctx->DT[--i] += 1;
   } while (ctx->DT[i] == 0 && i > 0);

   ctx->data_idx = 0;
   return 0;
}

int get_bytes(cprng_ctx *ctx, uint8_t *buf, uint32_t nbytes) { 
   if (ctx->flags == CPRNG_INVALID) {
      return -1;
   }

   uint8_t *ptr = buf;
   uint32_t byte_count = (uint32_t)nbytes;

   while (byte_count > 0) {
      uint32_t avail = sizeof(ctx->data) - ctx->data_idx;
      if (avail == 0 && _get_more_bytes(ctx) < 0) {
         memset(buf, 0, nbytes);
         return -1;
      }
      if (byte_count <= avail) {
         //everything we need is available
         memcpy(ptr, ctx->data + ctx->data_idx, byte_count);
         ctx->data_idx += byte_count;
         break;
      }
      else {
         //take everything that's available
         memcpy(ptr, ctx->data + ctx->data_idx, avail);
         ctx->data_idx += avail;
         ptr += avail;
         byte_count -= avail;
      }
   }

   return (int)nbytes;
}

