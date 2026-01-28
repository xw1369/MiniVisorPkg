/** @file
  MiniVisor Memory Safety Framework Header (Stub Implementation)
  
  This file provides stub definitions for the memory safety framework 
  referenced in the MiniVisor drivers to allow compilation.
  
  Copyright (c) 2024, MiniVisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __MINI_VISOR_MEM_SAFETY_H__
#define __MINI_VISOR_MEM_SAFETY_H__

#include "../MdePkg/Include/Uefi.h"

//
// Memory Safety Definitions
//
#ifndef MAX_SAFE_BUFFER_SIZE
#define MAX_SAFE_BUFFER_SIZE  (1024 * 1024)  // 1MB max buffer size
#endif

//
// Atomic Operations (Simple implementations for UEFI)
//
#ifndef ATOMIC_ADD
#define ATOMIC_ADD(ptr, value) \
  do { \
    *(ptr) += (value); \
  } while (0)
#endif

#ifndef ATOMIC_SUB
#define ATOMIC_SUB(ptr, value) \
  do { \
    *(ptr) -= (value); \
  } while (0)
#endif

#ifndef ATOMIC_INC
#define ATOMIC_INC(ptr) \
  do { \
    (*(ptr))++; \
  } while (0)
#endif

#ifndef ATOMIC_DEC
#define ATOMIC_DEC(ptr) \
  do { \
    (*(ptr))--; \
  } while (0)
#endif

//
// Memory Safety Function Prototypes (Stub)
//
EFI_STATUS
ValidateBufferBounds (
  IN VOID *Buffer,
  IN UINTN Size,
  IN UINTN MaxSize
  );

EFI_STATUS
SecureZeroMemory (
  IN OUT VOID *Buffer,
  IN UINTN Size
  );

//
// Memory Safety Macros
//
#ifndef VALIDATE_POINTER
#define VALIDATE_POINTER(ptr) ((ptr) != NULL ? EFI_SUCCESS : EFI_INVALID_PARAMETER)
#endif

#define SAFE_BUFFER_CHECK(buf, size) \
  ((buf) != NULL && (size) <= MAX_SAFE_BUFFER_SIZE ? EFI_SUCCESS : EFI_INVALID_PARAMETER)

#endif // __MINI_VISOR_MEM_SAFETY_H__