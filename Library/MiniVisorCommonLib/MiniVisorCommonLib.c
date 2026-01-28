/**
  Safe memory allocation with comprehensive error handling.
  
  @param[in] Size          Size in bytes to allocate.
  @param[out] Buffer       Pointer to receive allocated buffer.
  @param[in] Description   Description for debugging.
  
  @retval EFI_SUCCESS      Memory allocated successfully.
  @retval Others           Allocation failed.
**/
EFI_STATUS
EFIAPI
SafeAllocatePool (
  IN UINTN Size,
  OUT VOID **Buffer,
  IN CHAR16 *Description
  )
{
  EFI_STATUS Status;
  
  VALIDATE_POINTER(Buffer);
  VALIDATE_SIZE(Size);
  
  *Buffer = NULL;
  Status = gBS->AllocatePool(EfiBootServicesData, Size, Buffer);
  
  if (EFI_ERROR(Status) || *Buffer == NULL) {
    DEBUG((EFI_D_ERROR, "Failed to allocate %d bytes for %s: %r\n", 
           Size, Description, Status));
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Security: Zero out allocated memory
  ZeroMem(*Buffer, Size);
  
  DEBUG((EFI_D_VERBOSE, "Allocated %d bytes for %s at %p\n", 
         Size, Description, *Buffer));
  
  return EFI_SUCCESS;
}

/**
  Safe page allocation with comprehensive error handling.
  
  @param[in] Type          Allocation type.
  @param[in] MemoryType    Memory type.
  @param[in] Pages         Number of pages to allocate.
  @param[out] Memory       Pointer to receive allocated memory address.
  @param[in] Description   Description for debugging.
  
  @retval EFI_SUCCESS      Pages allocated successfully.
  @retval Others           Allocation failed.
**/
EFI_STATUS
EFIAPI
SafeAllocatePages (
  IN EFI_ALLOCATE_TYPE Type,
  IN EFI_MEMORY_TYPE MemoryType,
  IN UINTN Pages,
  OUT EFI_PHYSICAL_ADDRESS *Memory,
  IN CHAR16 *Description
  )
{
  EFI_STATUS Status;
  
  VALIDATE_POINTER(Memory);
  VALIDATE_POINTER(Description);
  
  if (Pages == 0 || Pages > MAX_SAFE_PAGE_COUNT) {
    DEBUG((EFI_D_ERROR, "Invalid page count: %d\n", Pages));
    return EFI_INVALID_PARAMETER;
  }
  
  *Memory = 0;
  Status = gBS->AllocatePages(Type, MemoryType, Pages, Memory);
  
  if (EFI_ERROR(Status) || *Memory == 0) {
    DEBUG((EFI_D_ERROR, "Failed to allocate %d pages for %s: %r\n", 
           Pages, Description, Status));
    return Status;
  }
  
  // Security: Zero out allocated pages
  ZeroMem((VOID*)(UINTN)*Memory, Pages * EFI_PAGE_SIZE);
  
  DEBUG((EFI_D_VERBOSE, "Allocated %d pages for %s at 0x%lx\n", 
         Pages, Description, *Memory));
  
  return EFI_SUCCESS;
}

/**
  Safe buffer cleanup with validation.
  
  @param[in,out] SafeBuf   Safe buffer structure to cleanup.
**/
VOID
EFIAPI
SafeBufferCleanup (
  IN OUT SAFE_BUFFER *SafeBuf
  )
{
  if (SafeBuf == NULL) {
    return;
  }
  
  if (SafeBuf->Allocated && SafeBuf->Buffer != NULL) {
    // Security: Zero out buffer before freeing
    ZeroMem(SafeBuf->Buffer, SafeBuf->Size);
    
    gBS->FreePool(SafeBuf->Buffer);
    SafeBuf->Buffer = NULL;
    SafeBuf->Size = 0;
    SafeBuf->Allocated = FALSE;
    
    DEBUG((EFI_D_VERBOSE, "Freed buffer for %s\n", SafeBuf->Description));
  }
}

/**
  Map error codes to standardized values.
  
  @param[in] OriginalStatus  Original error status.
  
  @retval EFI_STATUS         Mapped error status.
**/
EFI_STATUS
EFIAPI
MapErrorCode (
  IN EFI_STATUS OriginalStatus
  )
{
  switch (OriginalStatus) {
    case EFI_SUCCESS:
    case EFI_BUFFER_TOO_SMALL:
    case EFI_NOT_FOUND:
    case EFI_ACCESS_DENIED:
    case EFI_INVALID_PARAMETER:
    case EFI_OUT_OF_RESOURCES:
    case EFI_UNSUPPORTED:
    case EFI_DEVICE_ERROR:
    case EFI_WRITE_PROTECTED:
    case EFI_ALREADY_STARTED:
    case EFI_NOT_READY:
    case EFI_TIMEOUT:
    case EFI_ABORTED:
    case EFI_CRC_ERROR:
    case EFI_SECURITY_VIOLATION:
      return OriginalStatus; // Keep standard EFI error codes as-is
      
    default:
      if (EFI_ERROR(OriginalStatus)) {
        return EFI_DEVICE_ERROR; // Map unknown errors to device error
      }
      return OriginalStatus;
  }
}

/**
  Safe cache lookup with timeout validation.
  
  @param[in] Key           Cache key.
  @param[out] Value        Cache value.
  @param[in] CurrentTime   Current timestamp.
  @param[in] Timeout       Timeout value.
  
  @retval TRUE             Cache hit.
  @retval FALSE            Cache miss.
**/
BOOLEAN
EFIAPI
SafeCacheLookup (
  IN UINT64 Key,
  OUT UINT64 *Value,
  IN UINT64 CurrentTime,
  IN UINT64 Timeout
  )
{
  UINT32 i;
  
  VALIDATE_POINTER(Value);
  
  for (i = 0; i < CACHE_SIZE; i++) {
    if (gTranslationCache[i].Valid && 
        gTranslationCache[i].Key == Key && 
        (CurrentTime - gTranslationCache[i].Timestamp) < Timeout) {
      *Value = gTranslationCache[i].Value;
      return TRUE;
    }
  }
  
  return FALSE;
}

/**
  Safe cache insertion with timestamp.
  
  @param[in] Key           Cache key.
  @param[in] Value         Cache value.
  @param[in] CurrentTime   Current timestamp.
**/
VOID
EFIAPI
SafeCacheInsert (
  IN UINT64 Key,
  IN UINT64 Value,
  IN UINT64 CurrentTime
  )
{
  gTranslationCache[gCacheIndex].Key = Key;
  gTranslationCache[gCacheIndex].Value = Value;
  gTranslationCache[gCacheIndex].Timestamp = CurrentTime;
  gTranslationCache[gCacheIndex].Valid = TRUE;
  
  gCacheIndex = (gCacheIndex + 1) % CACHE_SIZE;
}
