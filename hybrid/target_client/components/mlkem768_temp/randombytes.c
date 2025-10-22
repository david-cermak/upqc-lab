#include "esp_random.h"

void randombytes(uint8_t *out, size_t outlen)
{
    esp_fill_random(out, outlen);
}
