/** @file
  Null library instance for BaseLib which can be included
  when a build needs to include base library functions but does
  not want to generate stack check failures.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Library/BaseLib.h>

// Basic memory functions
VOID *
EFIAPI
CopyMem (
  OUT VOID       *DestinationBuffer,
  IN  CONST VOID *SourceBuffer,
  IN  UINTN      Length
  )
{
  // Simple implementation
  if (DestinationBuffer == NULL || SourceBuffer == NULL) {
    return DestinationBuffer;
  }
  
  if (DestinationBuffer < SourceBuffer) {
    // Copy forward
    for (UINTN i = 0; i < Length; i++) {
      ((UINT8*)DestinationBuffer)[i] = ((UINT8*)SourceBuffer)[i];
    }
  } else {
    // Copy backward to handle overlapping
    for (UINTN i = Length; i > 0; i--) {
      ((UINT8*)DestinationBuffer)[i-1] = ((UINT8*)SourceBuffer)[i-1];
    }
  }
  
  return DestinationBuffer;
}

VOID *
EFIAPI
SetMem (
  OUT VOID  *Buffer,
  IN  UINTN Size,
  IN  UINT8 Value
  )
{
  if (Buffer == NULL) {
    return Buffer;
  }
  
  for (UINTN i = 0; i < Size; i++) {
    ((UINT8*)Buffer)[i] = Value;
  }
  
  return Buffer;
}

VOID *
EFIAPI
SetMem16 (
  OUT VOID   *Buffer,
  IN  UINTN  Size,
  IN  UINT16 Value
  )
{
  if (Buffer == NULL) {
    return Buffer;
  }
  
  UINTN count = Size / sizeof(UINT16);
  for (UINTN i = 0; i < count; i++) {
    ((UINT16*)Buffer)[i] = Value;
  }
  
  return Buffer;
}

VOID *
EFIAPI
SetMem32 (
  OUT VOID   *Buffer,
  IN  UINTN  Size,
  IN  UINT32 Value
  )
{
  if (Buffer == NULL) {
    return Buffer;
  }
  
  UINTN count = Size / sizeof(UINT32);
  for (UINTN i = 0; i < count; i++) {
    ((UINT32*)Buffer)[i] = Value;
  }
  
  return Buffer;
}

VOID *
EFIAPI
SetMem64 (
  OUT VOID   *Buffer,
  IN  UINTN  Size,
  IN  UINT64 Value
  )
{
  if (Buffer == NULL) {
    return Buffer;
  }
  
  UINTN count = Size / sizeof(UINT64);
  for (UINTN i = 0; i < count; i++) {
    ((UINT64*)Buffer)[i] = Value;
  }
  
  return Buffer;
}

VOID *
EFIAPI
ZeroMem (
  OUT VOID  *Buffer,
  IN  UINTN Size
  )
{
  return SetMem(Buffer, Size, 0);
}

// Basic string functions
UINTN
EFIAPI
StrLen (
  IN CONST CHAR16 *String
  )
{
  if (String == NULL) {
    return 0;
  }
  
  UINTN length = 0;
  while (String[length] != L'\0') {
    length++;
  }
  
  return length;
}

UINTN
EFIAPI
StrSize (
  IN CONST CHAR16 *String
  )
{
  return (StrLen(String) + 1) * sizeof(CHAR16);
}

// Basic math functions
UINT64
EFIAPI
LShiftU64 (
  IN UINT64  Operand,
  IN UINTN   Count
  )
{
  return Operand << Count;
}

UINT64
EFIAPI
RShiftU64 (
  IN UINT64  Operand,
  IN UINTN   Count
  )
{
  return Operand >> Count;
}

UINT64
EFIAPI
MultU64x32 (
  IN UINT64  Multiplicand,
  IN UINT32  Multiplier
  )
{
  return Multiplicand * Multiplier;
}

UINT64
EFIAPI
DivU64x32 (
  IN UINT64  Dividend,
  IN UINT32  Divisor
  )
{
  if (Divisor == 0) {
    return 0;
  }
  return Dividend / Divisor;
}

// CPU functions
VOID
EFIAPI
CpuDeadLoop (
  VOID
  )
{
  while (TRUE) {
    // Do nothing
  }
}

// Memory fence functions
VOID
EFIAPI
MemoryFence (
  VOID
  )
{
  // Simple memory fence
  volatile UINT32 dummy = 0;
  dummy = dummy;
}

// Stack functions
VOID
EFIAPI
SwitchStack (
  IN SWITCH_STACK_ENTRY_POINT EntryPoint,
  IN VOID                     *Context1,   OPTIONAL
  IN VOID                     *Context2,   OPTIONAL
  IN VOID                     *NewStack
  )
{
  // Simple implementation - just call the entry point
  if (EntryPoint != NULL) {
    EntryPoint(Context1, Context2);
  }
}
