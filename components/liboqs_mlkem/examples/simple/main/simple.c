#include <stdio.h>
#include "mlkem768.h"
#include "esp_log.h"
#define TAG "simple"

void app_main(void)
{
    mlkem768_ctx_t ctx;
    mlkem768_init(&ctx);
    mlkem768_keypair(&ctx);
    mlkem768_encaps(&ctx, ctx.public_key);
    mlkem768_decaps(&ctx, ctx.ciphertext);
    mlkem768_cleanup(&ctx);
    
}
