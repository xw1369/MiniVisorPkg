#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/BlockIo.h>
#include <Protocol/Smbios.h>
#include <Protocol/LoadedImage.h>
#include <IndustryStandard/SmBios.h>
#include <Guid/FileInfo.h>
#include <Guid/FileSystemInfo.h>

// Hardware data structure
#pragma pack(1)
typedef struct {
  UINT32 Magic;                    // 'HWID'
  UINT32 Version;                  // Version number  
  UINT32 CpuSignature;            // CPU signature from CPUID
  UINT32 CpuBrandHash;            // Hash of CPU brand string
  UINT64 CpuSerialNumber;         // CPU serial if available
  UINT64 SystemTime;              // System time at collection
  UINT32 MemorySize;              // Total memory size
  UINT32 PciDeviceCount;          // Number of PCI devices
  UINT32 MainboardSerialHash;     // Hash of mainboard serial
  CHAR8  CpuBrandString[64];      // CPU brand string
  CHAR8  MainboardSerial[32];     // Mainboard serial number
  CHAR8  SystemSerial[32];        // System serial number
  CHAR8  ManufacturerInfo[64];    // Manufacturer information
  UINT64 CollectionTime;          // Collection timestamp
  UINT32 Checksum;                // Data integrity checksum
} HARDWARE_DATA;
#pragma pack()

/**
 * Calculate simple checksum
 */
UINT32
CalculateChecksum(UINT8 *Data, UINTN Length)
{
  UINT32 Sum = 0;
  UINTN i;
  
  for (i = 0; i < Length; i++) {
    Sum += Data[i];
  }
  
  return ~Sum + 1;
}

/**
 * Calculate hash of a string
 */
UINT32
CalculateStringHash(CHAR8 *String)
{
  UINT32 Hash = 5381;
  UINTN i;
  
  if (String == NULL) return 0;
  
  for (i = 0; String[i] != '\0'; i++) {
    Hash = ((Hash << 5) + Hash) + String[i];
  }
  
  return Hash;
}

/**
 * Get CPU information using CPUID
 */
VOID
GetCpuInformation(HARDWARE_DATA *Data)
{
  UINT32 CpuidEax, CpuidEbx, CpuidEcx, CpuidEdx;
  CHAR8 *BrandPtr;
  UINTN i;
  
  Print(L"Collecting CPU information...\n");
  
  // Get CPU signature (EAX=1)
  AsmCpuid(1, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
  Data->CpuSignature = CpuidEax;
  
  Print(L"CPU Signature: 0x%08X\n", Data->CpuSignature);
  
  // Try to get CPU brand string (EAX=0x80000002-0x80000004)
  ZeroMem(Data->CpuBrandString, sizeof(Data->CpuBrandString));
  BrandPtr = Data->CpuBrandString;
  
  // Check if extended CPUID is supported
  AsmCpuid(0x80000000, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
  if (CpuidEax >= 0x80000004) {
    // Get brand string parts
    for (i = 0x80000002; i <= 0x80000004; i++) {
      AsmCpuid(i, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
      CopyMem(BrandPtr, &CpuidEax, 4);
      CopyMem(BrandPtr + 4, &CpuidEbx, 4);
      CopyMem(BrandPtr + 8, &CpuidEcx, 4);
      CopyMem(BrandPtr + 12, &CpuidEdx, 4);
      BrandPtr += 16;
    }
  } else {
    AsciiStrCpyS(Data->CpuBrandString, sizeof(Data->CpuBrandString), "Unknown CPU");
  }
  
  // Calculate brand hash
  Data->CpuBrandHash = CalculateStringHash(Data->CpuBrandString);
  
  Print(L"CPU Brand: %a\n", Data->CpuBrandString);
  Print(L"CPU Brand Hash: 0x%08X\n", Data->CpuBrandHash);
  
  // Try to get CPU serial (not always available)
  // Only use CPUID.03H if supported; otherwise derive a stable alternative
  AsmCpuid(0, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
  if (CpuidEax >= 3) {
    AsmCpuid(3, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
    Data->CpuSerialNumber = ((UINT64)CpuidEdx << 32) | CpuidEcx;
  } else {
    AsmCpuid(1, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
    Data->CpuSerialNumber = ((UINT64)CpuidEax << 32) |
                            ((UINT64)CpuidEbx & 0xFFFFFF00) |
                            (CpuidEbx & 0xFF);
  }
}

/**
 * Get system time
 */
VOID
GetSystemTime(HARDWARE_DATA *Data)
{
  EFI_STATUS Status;
  EFI_TIME Time;
  
  Print(L"Getting system time...\n");
  
  Status = gRT->GetTime(&Time, NULL);
  if (EFI_ERROR(Status)) {
    Print(L"Warning: Cannot get system time: %r\n", Status);
    Data->SystemTime = 0;
    Data->CollectionTime = 0;
  } else {
    // Convert to simple timestamp
    Data->SystemTime = (UINT64)Time.Year * 10000000000ULL +
                       (UINT64)Time.Month * 100000000ULL +
                       (UINT64)Time.Day * 1000000ULL +
                       (UINT64)Time.Hour * 10000ULL +
                       (UINT64)Time.Minute * 100ULL +
                       (UINT64)Time.Second;
    Data->CollectionTime = Data->SystemTime;
    
    Print(L"System time: %04d-%02d-%02d %02d:%02d:%02d\n",
          Time.Year, Time.Month, Time.Day, Time.Hour, Time.Minute, Time.Second);
  }
}

/**
 * Helper function to get SMBIOS string by index
 */
CHAR8*
GetSmbiosStringByIndex(EFI_SMBIOS_TABLE_HEADER *Record, UINT8 StringIndex)
{
  CHAR8 *StringPtr;
  UINTN CurrentIndex;
  
  if (StringIndex == 0) {
    return NULL;
  }
  
  // Point to string section (after fixed part)
  StringPtr = (CHAR8*)Record + Record->Length;
  CurrentIndex = 1;
  
  // Navigate through strings
  while (*StringPtr != 0 || *(StringPtr + 1) != 0) {
    if (CurrentIndex == StringIndex) {
      return (*StringPtr != 0) ? StringPtr : NULL;
    }
    
    // Skip to next string
    while (*StringPtr != 0) {
      StringPtr++;
    }
    StringPtr++; // Skip null terminator
    CurrentIndex++;
  }
  
  return NULL;
}

/**
 * Get SMBIOS information
 */
VOID
GetSmbiosInformation(HARDWARE_DATA *Data)
{
  EFI_STATUS Status;
  EFI_SMBIOS_PROTOCOL *Smbios;
  EFI_SMBIOS_HANDLE SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER *Record;
  SMBIOS_TABLE_TYPE1 *Type1Record;
  SMBIOS_TABLE_TYPE2 *Type2Record;
  EFI_SMBIOS_TYPE RequestedType;
  CHAR8 *StringValue;
  UINTN RecordCount = 0;
  
  Print(L"Collecting SMBIOS information...\n");
  
  // Initialize strings with default values
  AsciiStrCpyS(Data->MainboardSerial, sizeof(Data->MainboardSerial), "Unknown");
  AsciiStrCpyS(Data->SystemSerial, sizeof(Data->SystemSerial), "Unknown");
  AsciiStrCpyS(Data->ManufacturerInfo, sizeof(Data->ManufacturerInfo), "Unknown");
  
  Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID**)&Smbios);
  if (EFI_ERROR(Status)) {
    Print(L"ERROR: SMBIOS protocol not available: %r\n", Status);
    Print(L"This may mean SMBIOS is not supported on this system.\n");
    return;
  }
  
  Print(L"SMBIOS protocol located successfully!\n");
  
  // Get System Information (Type 1) - with specific type filter
  RequestedType = 1;  // System Information
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = Smbios->GetNext(Smbios, &SmbiosHandle, &RequestedType, &Record, NULL);
  
  if (!EFI_ERROR(Status)) {
    Type1Record = (SMBIOS_TABLE_TYPE1*)Record;
    Print(L"Found SMBIOS Type 1 (System Information) record\n");
    
    // Get system serial number
    if (Type1Record->SerialNumber > 0) {
      StringValue = GetSmbiosStringByIndex(Record, Type1Record->SerialNumber);
      if (StringValue != NULL && AsciiStrLen(StringValue) > 0) {
        AsciiStrnCpyS(Data->SystemSerial, sizeof(Data->SystemSerial), 
                      StringValue, sizeof(Data->SystemSerial) - 1);
        Print(L"System Serial Number: %a\n", Data->SystemSerial);
      }
    }
    
    // Get manufacturer
    if (Type1Record->Manufacturer > 0) {
      StringValue = GetSmbiosStringByIndex(Record, Type1Record->Manufacturer);
      if (StringValue != NULL && AsciiStrLen(StringValue) > 0) {
        AsciiStrnCpyS(Data->ManufacturerInfo, sizeof(Data->ManufacturerInfo),
                      StringValue, sizeof(Data->ManufacturerInfo) - 1);
        Print(L"Manufacturer: %a\n", Data->ManufacturerInfo);
      }
    }
    
    // Get product name for additional info
    if (Type1Record->ProductName > 0) {
      StringValue = GetSmbiosStringByIndex(Record, Type1Record->ProductName);
      if (StringValue != NULL && AsciiStrLen(StringValue) > 0) {
        Print(L"Product Name: %a\n", StringValue);
      }
    }
  } else {
    Print(L"Warning: No SMBIOS Type 1 record found: %r\n", Status);
  }
  
  // Get Baseboard Information (Type 2) - with specific type filter
  RequestedType = 2;  // Baseboard Information  
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = Smbios->GetNext(Smbios, &SmbiosHandle, &RequestedType, &Record, NULL);
  
  if (!EFI_ERROR(Status)) {
    Type2Record = (SMBIOS_TABLE_TYPE2*)Record;
    Print(L"Found SMBIOS Type 2 (Baseboard Information) record\n");
    
    // Get baseboard serial number
    if (Type2Record->SerialNumber > 0) {
      StringValue = GetSmbiosStringByIndex(Record, Type2Record->SerialNumber);
      if (StringValue != NULL && AsciiStrLen(StringValue) > 0) {
        AsciiStrnCpyS(Data->MainboardSerial, sizeof(Data->MainboardSerial),
                      StringValue, sizeof(Data->MainboardSerial) - 1);
        Print(L"Mainboard Serial Number: %a\n", Data->MainboardSerial);
      }
    }
    
    // Get baseboard manufacturer for additional info
    if (Type2Record->Manufacturer > 0) {
      StringValue = GetSmbiosStringByIndex(Record, Type2Record->Manufacturer);
      if (StringValue != NULL && AsciiStrLen(StringValue) > 0) {
        Print(L"Baseboard Manufacturer: %a\n", StringValue);
      }
    }
  } else {
    Print(L"Warning: No SMBIOS Type 2 record found: %r\n", Status);
  }
  
  // Try to enumerate all SMBIOS records for debugging
  Print(L"Enumerating all SMBIOS records for debugging...\n");
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = Smbios->GetNext(Smbios, &SmbiosHandle, NULL, &Record, NULL);
  while (!EFI_ERROR(Status) && RecordCount < 50) {  // Limit to prevent infinite loop
    Print(L"Found SMBIOS Type %d record\n", Record->Type);
    RecordCount++;
    Status = Smbios->GetNext(Smbios, &SmbiosHandle, NULL, &Record, NULL);
  }
  Print(L"Total SMBIOS records found: %d\n", RecordCount);
  
  // Calculate mainboard serial hash
  Data->MainboardSerialHash = CalculateStringHash(Data->MainboardSerial);
  
  Print(L"Final results:\n");
  Print(L"  System Serial: %a\n", Data->SystemSerial);
  Print(L"  Mainboard Serial: %a\n", Data->MainboardSerial);
  Print(L"  Manufacturer: %a\n", Data->ManufacturerInfo);
  Print(L"  Mainboard Serial Hash: 0x%08X\n", Data->MainboardSerialHash);
}

/**
 * Get memory information
 */
VOID
GetMemoryInformation(HARDWARE_DATA *Data)
{
  EFI_STATUS Status;
  UINTN MemoryMapSize = 0;
  EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
  UINTN MapKey;
  UINTN DescriptorSize;
  UINT32 DescriptorVersion;
  UINT64 TotalMemory = 0;
  UINT64 UsableMemory = 0;
  UINTN EntryCount = 0;
  
  Print(L"Collecting memory information...\n");
  
  // First call to get required buffer size
  Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  
  if (Status != EFI_BUFFER_TOO_SMALL) {
    Print(L"ERROR: Unexpected GetMemoryMap status: %r\n", Status);
    Data->MemorySize = 0;
    return;
  }
  
  Print(L"Required memory map size: %lu bytes\n", (UINT64)MemoryMapSize);
  Print(L"Descriptor size: %lu bytes\n", (UINT64)DescriptorSize);
  
  // Add extra space for potential changes during allocation
  MemoryMapSize += 8 * DescriptorSize;
  MemoryMap = AllocatePool(MemoryMapSize);
  
  if (MemoryMap == NULL) {
    Print(L"ERROR: Failed to allocate memory for memory map\n");
    Data->MemorySize = 0;
    return;
  }
  
  Print(L"Memory map buffer allocated successfully\n");
  
  // Get actual memory map
  Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  
  if (EFI_ERROR(Status)) {
    Print(L"ERROR: Failed to get memory map: %r\n", Status);
    FreePool(MemoryMap);
    Data->MemorySize = 0;
    return;
  }
  
  Print(L"Memory map retrieved successfully\n");
  Print(L"Memory descriptor version: 0x%X\n", DescriptorVersion);
  
  EntryCount = MemoryMapSize / DescriptorSize;
  Print(L"Memory map entries: %lu\n", (UINT64)EntryCount);
  
  EFI_MEMORY_DESCRIPTOR *Desc = MemoryMap;
  for (UINTN i = 0; i < EntryCount; i++) {
    UINT64 RegionSize = Desc->NumberOfPages * EFI_PAGE_SIZE;
    TotalMemory += RegionSize;
    
    // Count usable memory (conventional memory)
    if (Desc->Type == EfiConventionalMemory ||
        Desc->Type == EfiBootServicesCode ||
        Desc->Type == EfiBootServicesData ||
        Desc->Type == EfiRuntimeServicesCode ||
        Desc->Type == EfiRuntimeServicesData) {
      UsableMemory += RegionSize;
    }
    
    // Debug: Print first few entries
    if (i < 5) {
      Print(L"Entry %lu: Type=%d, Start=0x%lX, Pages=%lX, Size=%dMB\n", 
            (UINT64)i, Desc->Type, Desc->PhysicalStart, Desc->NumberOfPages, 
            (UINT32)(RegionSize / (1024 * 1024)));
    }
    
    Desc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)Desc + DescriptorSize);
  }
  
  FreePool(MemoryMap);
  
  Data->MemorySize = (UINT32)(TotalMemory / (1024 * 1024)); // Convert to MB
  
  Print(L"Memory analysis results:\n");
  Print(L"  Total Memory: %d MB (%ld bytes)\n", Data->MemorySize, TotalMemory);
  Print(L"  Usable Memory: %d MB (%ld bytes)\n", (UINT32)(UsableMemory / (1024 * 1024)), UsableMemory);
  Print(L"  Total Entries: %lu\n", (UINT64)EntryCount);
  
  if (Data->MemorySize == 0) {
    Print(L"WARNING: No memory detected - this may indicate a problem!\n");
  }
}

/**
 * Save hardware data to multiple files
 */
EFI_STATUS
SaveHardwareData(EFI_HANDLE ImageHandle, HARDWARE_DATA *Data)
{
  EFI_STATUS Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_PROTOCOL *RootDir;
  EFI_FILE_PROTOCOL *FileHandle;
  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  EFI_HANDLE *PreferredHandles;
  UINTN BufferSize;
  UINTN ExpectedSize;
  UINTN Index;
  BOOLEAN SaveSuccess = FALSE;
  BOOLEAN IsRemovable;
  UINTN FsInfoSize;
  EFI_FILE_SYSTEM_INFO *FsInfo;
  
  CHAR16 *FileNames[] = {
    L"hardware_info.bin",
    L"hwinfo.dat", 
    L"hardware_data.bin",
    L"system_info.dat"
  };
  UINTN FileNameCount = sizeof(FileNames) / sizeof(FileNames[0]);
  
  Print(L"Saving hardware data to files...\n");
  
  // Calculate checksum
  Data->Checksum = CalculateChecksum((UINT8*)Data, sizeof(HARDWARE_DATA) - sizeof(Data->Checksum));
  
  ExpectedSize = sizeof(HARDWARE_DATA);
  BufferSize = ExpectedSize;
  
  // First try the device where this image was loaded from (typically the USB stick)
  {
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
    Status = gBS->HandleProtocol(
      ImageHandle,
      &gEfiLoadedImageProtocolGuid,
      (VOID**)&LoadedImage
    );
    if (!EFI_ERROR(Status) && LoadedImage != NULL && LoadedImage->DeviceHandle != NULL) {
      Status = gBS->HandleProtocol(
        LoadedImage->DeviceHandle,
        &gEfiSimpleFileSystemProtocolGuid,
        (VOID**)&FileSystem
      );
      if (!EFI_ERROR(Status)) {
        Print(L"Trying image device volume first...\n");
        Status = FileSystem->OpenVolume(FileSystem, &RootDir);
        if (!EFI_ERROR(Status)) {
          // Query FS info for this volume
          FsInfoSize = 0;
          FsInfo = NULL;
          Status = RootDir->GetInfo(RootDir, &gEfiFileSystemInfoGuid, &FsInfoSize, NULL);
          if (Status == EFI_BUFFER_TOO_SMALL) {
            FsInfo = AllocatePool(FsInfoSize);
            if (FsInfo != NULL) {
              Status = RootDir->GetInfo(RootDir, &gEfiFileSystemInfoGuid, &FsInfoSize, FsInfo);
              if (!EFI_ERROR(Status)) {
                Print(L"[Image Device] Volume: '%s', Size=%luMB, Free=%luMB, ReadOnly=%s\n",
                      FsInfo->VolumeLabel != NULL ? FsInfo->VolumeLabel : L"(no label)",
                      (UINT64)(FsInfo->VolumeSize / (1024 * 1024)),
                      (UINT64)(FsInfo->FreeSpace / (1024 * 1024)),
                      FsInfo->ReadOnly ? L"Yes" : L"No");
              }
            }
          }
          
          for (UINTN FileIndex = 0; FileIndex < FileNameCount; FileIndex++) {
            Status = RootDir->Open(
              RootDir,
              &FileHandle,
              FileNames[FileIndex],
              EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
              EFI_FILE_ARCHIVE
            );
            if (!EFI_ERROR(Status)) {
              BufferSize = ExpectedSize;
              Status = FileHandle->Write(FileHandle, &BufferSize, Data);
              if (!EFI_ERROR(Status) && BufferSize == ExpectedSize) {
                FileHandle->Flush(FileHandle);
                Print(L"SUCCESS: Saved to image device as %s (%lu bytes)\n", FileNames[FileIndex], (UINT64)BufferSize);
                SaveSuccess = TRUE;
              }
              FileHandle->Close(FileHandle);
              if (SaveSuccess) break;
            }
          }
          RootDir->Close(RootDir);
          if (FsInfo != NULL) { FreePool(FsInfo); FsInfo = NULL; }
          if (SaveSuccess) {
            Print(L"Final result: SUCCESS - Hardware data saved on image device!\n");
            return EFI_SUCCESS;
          }
        }
      }
    }
  }

  // Locate all file system handles
  Status = gBS->LocateHandleBuffer(
    ByProtocol,
    &gEfiSimpleFileSystemProtocolGuid,
    NULL,
    &HandleCount,
    &HandleBuffer
  );
  
  if (EFI_ERROR(Status)) {
    Print(L"Error: Cannot locate file systems: %r\n", Status);
    return Status;
  }
  
  Print(L"Found %lu file systems\n", (UINT64)HandleCount);

  PreferredHandles = AllocatePool(sizeof(EFI_HANDLE) * HandleCount);
  if (PreferredHandles == NULL) {
    FreePool(HandleBuffer);
    return EFI_OUT_OF_RESOURCES;
  }

  // Fill preferred order: removable first, then non-removable
  UINTN PreferredCount = 0;
  for (Index = 0; Index < HandleCount; Index++) {
    EFI_BLOCK_IO_PROTOCOL *BlockIo;
    Status = gBS->HandleProtocol(
      HandleBuffer[Index],
      &gEfiBlockIoProtocolGuid,
      (VOID**)&BlockIo
    );
    if (!EFI_ERROR(Status) && BlockIo != NULL && BlockIo->Media != NULL && BlockIo->Media->RemovableMedia) {
      PreferredHandles[PreferredCount++] = HandleBuffer[Index];
    }
  }
  for (Index = 0; Index < HandleCount; Index++) {
    EFI_BLOCK_IO_PROTOCOL *BlockIo;
    Status = gBS->HandleProtocol(
      HandleBuffer[Index],
      &gEfiBlockIoProtocolGuid,
      (VOID**)&BlockIo
    );
    if (!( !EFI_ERROR(Status) && BlockIo != NULL && BlockIo->Media != NULL && BlockIo->Media->RemovableMedia)) {
      PreferredHandles[PreferredCount++] = HandleBuffer[Index];
    }
  }
  
  // Try each file system in preferred order (USB/removable first)
  for (Index = 0; Index < PreferredCount; Index++) {
    EFI_BLOCK_IO_PROTOCOL *BlockIo;
    Status = gBS->HandleProtocol(
      PreferredHandles[Index],
      &gEfiBlockIoProtocolGuid,
      (VOID**)&BlockIo
    );
    IsRemovable = (!EFI_ERROR(Status) && BlockIo != NULL && BlockIo->Media != NULL && BlockIo->Media->RemovableMedia);

    Print(L"Trying file system %lu/%lu (%s)...\n", (UINT64)(Index + 1), (UINT64)PreferredCount, IsRemovable ? L"Removable" : L"Fixed");

    Status = gBS->HandleProtocol(
      PreferredHandles[Index],
      &gEfiSimpleFileSystemProtocolGuid,
      (VOID**)&FileSystem
    );
    
    if (EFI_ERROR(Status)) {
      Print(L"Warning: Cannot get file system protocol %u: %r\n", Index, Status);
      continue;
    }
    
    Status = FileSystem->OpenVolume(FileSystem, &RootDir);
    if (EFI_ERROR(Status)) {
      Print(L"Warning: Cannot open root volume %u: %r\n", Index, Status);
      continue;
    }
    
    // Query and print file system information
    FsInfoSize = 0;
    FsInfo = NULL;
    Status = RootDir->GetInfo(RootDir, &gEfiFileSystemInfoGuid, &FsInfoSize, NULL);
    if (Status == EFI_BUFFER_TOO_SMALL) {
      FsInfo = AllocatePool(FsInfoSize);
      if (FsInfo != NULL) {
        Status = RootDir->GetInfo(RootDir, &gEfiFileSystemInfoGuid, &FsInfoSize, FsInfo);
        if (!EFI_ERROR(Status)) {
          Print(L"Volume: '%s', Size=%luMB, Free=%luMB, BlockSize=%u, ReadOnly=%s\n",
                FsInfo->VolumeLabel != NULL ? FsInfo->VolumeLabel : L"(no label)",
                (UINT64)(FsInfo->VolumeSize / (1024 * 1024)),
                (UINT64)(FsInfo->FreeSpace / (1024 * 1024)),
                FsInfo->BlockSize,
                FsInfo->ReadOnly ? L"Yes" : L"No");
        }
      }
    }
    
    // Try each file name
    for (UINTN FileIndex = 0; FileIndex < FileNameCount; FileIndex++) {
      Status = RootDir->Open(
        RootDir,
        &FileHandle,
        FileNames[FileIndex],
        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
        EFI_FILE_ARCHIVE
      );
      
      if (!EFI_ERROR(Status)) {
        Print(L"Created file: %s\n", FileNames[FileIndex]);
        
        BufferSize = ExpectedSize;
        Status = FileHandle->Write(FileHandle, &BufferSize, Data);
        if (!EFI_ERROR(Status) && BufferSize == ExpectedSize) {
          EFI_STATUS FlushStatus = FileHandle->Flush(FileHandle);
          if (EFI_ERROR(FlushStatus)) {
            Print(L"Warning: Flush failed for %s: %r\n", FileNames[FileIndex], FlushStatus);
          }
          Print(L"SUCCESS: Hardware data saved to %s (%lu bytes)\n", 
                FileNames[FileIndex], (UINT64)BufferSize);
          SaveSuccess = TRUE;
        } else {
          Print(L"Warning: Write failed for %s: %r (wrote %lu/%lu bytes)\n",
                FileNames[FileIndex], Status, (UINT64)BufferSize, (UINT64)ExpectedSize);
        }
        
        FileHandle->Close(FileHandle);
        
        if (SaveSuccess) break; // Success, don't try more files on this volume
      }
    }
    
    RootDir->Close(RootDir);
    if (FsInfo != NULL) {
      FreePool(FsInfo);
      FsInfo = NULL;
    }
    
    if (SaveSuccess) break; // Success, don't try more volumes
  }
  
  FreePool(PreferredHandles);
  FreePool(HandleBuffer);
  
  if (SaveSuccess) {
    Print(L"Final result: SUCCESS - Hardware data saved!\n");
    return EFI_SUCCESS;
  } else {
    Print(L"Final result: FAILED - Could not save to any drive!\n");
    return EFI_NOT_FOUND;
  }
}

/**
 * Display collected hardware information
 */
VOID
DisplayHardwareInfo(HARDWARE_DATA *Data)
{
  Print(L"\n=== COLLECTED HARDWARE INFORMATION ===\n");
  Print(L"Magic Number: 0x%08X ('%c%c%c%c')\n", 
        Data->Magic,
        (CHAR8)(Data->Magic & 0xFF),
        (CHAR8)((Data->Magic >> 8) & 0xFF),
        (CHAR8)((Data->Magic >> 16) & 0xFF),
        (CHAR8)((Data->Magic >> 24) & 0xFF));
  Print(L"Version: 0x%08X\n", Data->Version);
  Print(L"CPU Signature: 0x%08X\n", Data->CpuSignature);
  Print(L"CPU Brand Hash: 0x%08X\n", Data->CpuBrandHash);
  Print(L"CPU Serial: 0x%016lX\n", Data->CpuSerialNumber);
  Print(L"System Time: 0x%016lX\n", Data->SystemTime);
  Print(L"Memory Size: %d MB\n", Data->MemorySize);
  Print(L"PCI Device Count: %d\n", Data->PciDeviceCount);
  Print(L"Mainboard Serial Hash: 0x%08X\n", Data->MainboardSerialHash);
  Print(L"CPU Brand: %a\n", Data->CpuBrandString);
  Print(L"Mainboard Serial: %a\n", Data->MainboardSerial);
  Print(L"System Serial: %a\n", Data->SystemSerial);
  Print(L"Manufacturer: %a\n", Data->ManufacturerInfo);
  Print(L"Collection Time: 0x%016lX\n", Data->CollectionTime);
  Print(L"Checksum: 0x%08X\n", Data->Checksum);
}

/**
 * Main entry point
 */
EFI_STATUS
EFIAPI
UefiMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
)
{
  EFI_STATUS Status;
  HARDWARE_DATA HardwareData;
  EFI_INPUT_KEY Key;
  
  Print(L"\n");
  Print(L"==================================================\n");
  Print(L"          HARDWARE COLLECTOR v3.0 (NO CHINESE)\n");
  Print(L"==================================================\n");
  Print(L"\n");
  
  Print(L"Testing basic file operations and hardware collection...\n");
  
  // Initialize data structure
  ZeroMem(&HardwareData, sizeof(HARDWARE_DATA));
  
  // Set magic number and version
  HardwareData.Magic = 0x44495748; // 'HWID'
  HardwareData.Version = 0x00030000; // v3.0
  
  // Step 1: Get system time
  Print(L"\nStep 1: Getting system time...\n");
  GetSystemTime(&HardwareData);
  
  // Step 2: Get CPU information  
  Print(L"\nStep 2: Getting CPU information...\n");
  GetCpuInformation(&HardwareData);
  
  // Step 3: Get memory information
  Print(L"\nStep 3: Getting memory information...\n");
  GetMemoryInformation(&HardwareData);
  
  // Step 4: Get SMBIOS information
  Print(L"\nStep 4: Getting SMBIOS information...\n");
  GetSmbiosInformation(&HardwareData);
  
  // Step 5: Set PCI device count (placeholder)
  HardwareData.PciDeviceCount = 0; // TODO: Implement PCI enumeration
  
  // Step 6: Display collected information
  Print(L"\nStep 5: Displaying collected information...\n");
  DisplayHardwareInfo(&HardwareData);
  
  // Step 7: Save data to file
  Print(L"\nStep 6: Saving data to files...\n");
  Status = SaveHardwareData(ImageHandle, &HardwareData);
  
  Print(L"\n");
  if (!EFI_ERROR(Status)) {
    Print(L"*** COMPLETE SUCCESS! ***\n");
    Print(L"\n");
    Print(L"Hardware information successfully collected and saved!\n");
    Print(L"\n");
    Print(L"Look for hardware_info.bin, hwinfo.dat, hardware_data.bin, or system_info.dat on your drive.\n");
  } else {
    Print(L"*** FAILED: Could not save hardware information! ***\n");
    Print(L"\n");
    Print(L"Error: %r\n", Status);
  }
  
  Print(L"\n");
  Print(L"Hardware collector execution completed.\n");
  Print(L"\n");
  Print(L"Press any key to continue or wait 10 seconds...\n");
  
  // Wait for key press or timeout
  for (UINTN i = 0; i < 100; i++) { // 10 seconds (100 * 100ms)
    Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
    if (!EFI_ERROR(Status)) {
      break;
    }
    gBS->Stall(100000); // 100ms
  }
  
  return EFI_SUCCESS;
}
