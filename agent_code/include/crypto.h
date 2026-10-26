#ifndef EMERALDSTRIKE_CRYPTO_H
#define EMERALDSTRIKE_CRYPTO_H

#include "common.h"

#define AES_BLOCK_SIZE   16
#define AES_KEY_SIZE     32
#define HMAC_SHA256_SIZE 32

BOOL aes256_encrypt(PINSTANCE inst, const BYTE* key, const BYTE* iv,
                    const BYTE* plain, DWORD plain_len,
                    BYTE** cipher, DWORD* cipher_len);

BOOL aes256_decrypt(PINSTANCE inst, const BYTE* key, const BYTE* iv,
                    const BYTE* cipher, DWORD cipher_len,
                    BYTE** plain, DWORD* plain_len);

BOOL hmac_sha256(PINSTANCE inst, const BYTE* key, DWORD key_len,
                 const BYTE* data, DWORD data_len, BYTE* output);

BOOL mythic_encrypt(PINSTANCE inst, const BYTE* plain, DWORD plain_len,
                    BYTE** out, DWORD* out_len);

BOOL mythic_decrypt(PINSTANCE inst, const BYTE* blob, DWORD blob_len,
                    BYTE** out, DWORD* out_len);

BOOL has_encryption_key(PINSTANCE inst);

VOID xor_bytes(BYTE* data, DWORD data_len, const BYTE* key, DWORD key_len);

#endif // EMERALDSTRIKE_CRYPTO_H
