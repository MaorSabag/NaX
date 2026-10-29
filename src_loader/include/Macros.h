#ifndef STARDUST_MACROS_H
#define STARDUST_MACROS_H

//
// utils macros
//
#define D_API( x )  __typeof__( x ) * x;
#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )
#define FUNC        D_SEC( B )
#define ST_READONLY __attribute__( ( section( ".rdata" ) ) )

//
// casting macros
//
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define U_PTR32( x ) ( ( ULONG    ) ( x ) )
#define U_PTR64( x ) ( ( ULONG64  ) ( x ) )
#define A_PTR( x )   ( ( PCHAR    ) ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )

//
// dereference memory macros
//
#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

//
// memory related macros
//
#define MmCopy __builtin_memcpy
#define MmSet  __stosb
#define MmZero RtlSecureZeroMemory

//
// page alignment helpers (LDR_ prefix avoids collisions with beacon headers)
//
#define LDR_PAGE_SIZE  0x1000
#define LDR_PAGE_MASK  0xFFF
#define ALIGN_UP( size, align ) ( ( (SIZE_T)(size) + (SIZE_T)(align) - 1 ) & ~( (SIZE_T)(align) - 1 ) )

//
// CFG / mitigation policy constants
//
#define LDR_PROCESS_CFG_GUARD_POLICY           7   /* ProcessControlFlowGuardPolicy                  */
#define LDR_CFG_CALL_TARGET_VALID              1   /* CFG_CALL_TARGET_VALID                           */
#define LDR_CFG_CALL_TARGET_CONVERT_EXPORT     4   /* CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID */

//
// instance related macros - TLS egghunter retrieval
// Walks TEB->TlsSlots[0..63], finds NtCurrentPeb() egg, reads next slot.
//
static __inline__ PVOID __TlsFindInstance( void ) {
    PVOID  peb = C_PTR( NtCurrentPeb() );
    PTEB   teb = NtCurrentTeb();
    for ( UINT32 i = 0; i < 63; i++ ) {
        if ( teb->TlsSlots[ i ] == peb )
            return teb->TlsSlots[ i + 1 ];
    }
    return C_PTR( 0 );
}
#define InstancePtr()     ( ( PINSTANCE ) __TlsFindInstance() )
#define Instance()        ( ( PINSTANCE ) __LocalInstance )
#define STARDUST_INSTANCE PINSTANCE __LocalInstance = InstancePtr();

//
// instance field shortcuts (ZPS Extending Stardust pattern)
//
#define MOD( x )          Instance()->Modules.x
#define API( x )          Instance()->Win32.x
#define RESOLVE( x, y )   ( API( x ) = (__typeof__( x )*)LdrFunction( MOD( y ), HASH_STR( #x ) ) )

//
// NaxHeader v2 - typed reads from on-disk header pointer
//
#define HDR_U32( h, off )   C_DEF32( C_PTR( U_PTR( h ) + (off) ) )
#define HDR_WSTR( h, off )  W_PTR( U_PTR( h ) + (off) )

//
// pointer past the loader blob = start of NaxHeader
//
#define LOADER_END()  C_PTR( U_PTR( Instance()->Base.Buffer ) + Instance()->Base.Length )

/* Clion IDE hacks */
#ifdef  __cplusplus
#define CONSTEXPR         constexpr
#define TEMPLATE_TYPENAME template <typename T>
#define INLINE            inline
#else
#define CONSTEXPR
#define TEMPLATE_TYPENAME
#define INLINE
#endif

#endif //STARDUST_MACROS_H
