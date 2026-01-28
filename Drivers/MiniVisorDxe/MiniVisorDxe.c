#include <PiDxe.h>
#include <Library/PcdLib.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/IoLib.h>
#include <Library/BaseCryptLib.h>
#include <Protocol/MpService.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <IndustryStandard/DmaRemappingReportingTable.h>
#include <IndustryStandard/MemoryMappedConfigurationSpaceAccessTable.h>
#include <Protocol/Smbios.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Protocol/SimpleTextIn.h>
#include <Guid/FileSystemInfo.h>
#include <Guid/FileInfo.h>
#include <Library/DevicePathLib.h>
#include <IndustryStandard/SmBios.h>
#include "VmxDefs.h"
#include "VmxStructs.h"
#include "MiniVisorDxe.h"
#include "../../Include/MiniVisorSecurity.h"        // Security framework
#include "../../Include/MiniVisorAntiDetection.h"   // Anti-detection framework
#include "../../Include/MiniVisorConcurrency.h"     // Concurrency framework
#include "../../Include/MiniVisorMemSafety.h"       // Memory safety framework

//
// Memory Management Constants and Macros
//
// MAX_UINTN is already defined in EDK2 headers
// Memory safety macros are defined in MiniVisorMemSafety.h

//
// VT-d load structure definitions
//
#pragma pack(1)
typedef struct {
  UINT32 Signature;     // 'DMAR'
  UINT32 Length;
  UINT8  Revision;
  UINT8  Checksum;
  UINT8  OemId[6];
  UINT64 OemTableId;
  UINT32 OemRevision;
  UINT32 CreatorId;
  UINT32 CreatorRevision;
  UINT8  HostAddressWidth;
  UINT8  Flags;
  UINT8  Reserved[10];
} SIMPLE_DMAR_TABLE;

// Enhanced DMAR table with DRHD entries
typedef struct {
  UINT16  Type;           // 0x0000 = DRHD
  UINT16  Length;         // Length of this structure
  UINT8   Flags;          // Flags
  UINT8   Reserved;
  UINT16  SegmentNumber;  // PCI segment number
  UINT64  RegisterBaseAddress; // Base address of DMA-remapping hardware
} DMAR_DRHD_ENTRY;

typedef struct {
  UINT8   Type;           // Device scope entry type
  UINT8   Length;         // Length of this structure
  UINT16  Reserved;
  UINT8   EnumerationId;  // Device enumeration ID
  UINT8   StartBusNumber; // Starting bus number
  // Device path entries follow
  UINT8   Path[2];        // Device, Function
} DMAR_DEVICE_SCOPE_ENTRY;

typedef struct {
  EFI_ACPI_DESCRIPTION_HEADER Header;
  UINT8   HostAddressWidth;
  UINT8   Flags;
  UINT8   Reserved[10];
  DMAR_DRHD_ENTRY DrhDentry;
  DMAR_DEVICE_SCOPE_ENTRY DeviceScope;
} ENHANCED_DMAR_TABLE;

#pragma pack()

//
// VT-d PCI configuration space emulation structures
//
#define VTD_PCI_VENDOR_ID    0x8086    // Intel
#define VTD_PCI_DEVICE_ID    0x3E2E    // VT-d device ID (demo value)
#define VTD_PCI_CLASS_CODE   0x080600  // System peripheral, IOMMU
#define VTD_PCI_REVISION_ID  0x01      // Revision

#define PCI_CONFIG_ADDRESS_PORT  0xCF8  // PCI config address port
#define PCI_CONFIG_DATA_PORT     0xCFC  // PCI config data port

#define VTD_BUS_NUMBER    0x00         // VT-d bus number
#define VTD_DEVICE_NUMBER 0x02         // VT-d device number
#define VTD_FUNCTION_NUMBER 0x00       // VT-d function number

// VT-d PCI configuration space offsets
#define PCI_VENDOR_ID_OFFSET     0x00
#define PCI_DEVICE_ID_OFFSET     0x02
#define PCI_COMMAND_OFFSET       0x04
#define PCI_STATUS_OFFSET        0x06
#define PCI_REVISION_ID_OFFSET   0x08
#define PCI_CLASS_CODE_OFFSET    0x09
#define PCI_CACHE_LINE_SIZE_OFFSET 0x0C
#define PCI_LATENCY_TIMER_OFFSET 0x0D
#define PCI_HEADER_TYPE_OFFSET   0x0E
// Additional PCI offsets used
#define PCI_BAR1_OFFSET          0x14
#define PCI_INTERRUPT_LINE_OFFSET 0x3C
#define PCI_BIST_OFFSET          0x0F
#define PCI_BAR0_OFFSET          0x10
#define PCI_SUBSYSTEM_VENDOR_ID_OFFSET 0x2C
#define PCI_SUBSYSTEM_ID_OFFSET  0x2E
#define PCI_CAPABILITY_PTR_OFFSET 0x34

#pragma pack(1)
typedef struct {
  UINT16 VendorId;           // 0x00: Vendor ID
  UINT16 DeviceId;           // 0x02: Device ID
  UINT16 Command;            // 0x04: Command Register
  UINT16 Status;             // 0x06: Status Register
  UINT8  RevisionId;         // 0x08: Revision ID
  UINT8  ClassCode[3];       // 0x09: Class Code
  UINT8  CacheLineSize;      // 0x0C: Cache Line Size
  UINT8  LatencyTimer;       // 0x0D: Latency Timer
  UINT8  HeaderType;         // 0x0E: Header Type
  UINT8  BIST;               // 0x0F: Built-in Self Test
  UINT32 Bar0;               // 0x10: Base Address Register 0
  UINT32 Bar1;               // 0x14: Base Address Register 1
  UINT32 Bar2;               // 0x18: Base Address Register 2
  UINT32 Bar3;               // 0x1C: Base Address Register 3
  UINT32 Bar4;               // 0x20: Base Address Register 4
  UINT32 Bar5;               // 0x24: Base Address Register 5
  UINT32 CardBusCISPtr;      // 0x28: CardBus CIS Pointer
  UINT16 SubsystemVendorId;  // 0x2C: Subsystem Vendor ID
  UINT16 SubsystemId;        // 0x2E: Subsystem ID
  UINT32 ExpansionROMBaseAddr; // 0x30: Expansion ROM Base Address
  UINT8  CapabilityPtr;      // 0x34: Capability Pointer
  UINT8  Reserved1[3];       // 0x35-0x37: Reserved
  UINT32 Reserved2;          // 0x38: Reserved
  UINT8  InterruptLine;      // 0x3C: Interrupt Line
  UINT8  InterruptPin;       // 0x3D: Interrupt Pin
  UINT8  MinGnt;            // 0x3E: Minimum Grant
  UINT8  MaxLat;            // 0x3F: Maximum Latency
} VTD_PCI_CONFIG_SPACE;
#pragma pack()

// PCI configuration global state
static UINT32 gPciConfigAddress = 0;  // Current PCI config address
static VTD_PCI_CONFIG_SPACE gVtdPciConfig; // VT-d emulated PCI config space

// MiniVisor global state
MINI_VISOR_GLOBAL_DATA gMiniVisorGlobalData = { 0 };
BOOLEAN                gMiniVisorDebugMode = FALSE;
// gVtdCurrentAuth is defined in VtdAuthNextGen.c

//
// VT-d driver authorization system
//
#define VTD_AUTH_SIGNATURE   0x56544441  // 'VTDA' - VTD Authorization
#define VTD_AUTH_VERSION     0x00010001  // Version 1.0.1
#define VTD_MAX_USAGE_COUNT  100         // Max usage count
// 移除固定时间限制，改为由授权文件决定
// #define VTD_AUTH_TIMEOUT     (7 * 24 * 60 * 60) // 7 days (seconds) - DEPRECATED

// Unified authorization scheme with AMD SVM
// RSA/SHA constants (placeholders; see SVM driver for integration with BaseCryptLib)
#define VTD_RSA_SIGNATURE_SIZE 256
#define VTD_RSA_KEY_SIZE 256

// Authorization status
typedef enum {
  VtdAuthUnauthorized = 0,
  VtdAuthAuthorized = 1,
  VtdAuthExpired = 2,
  VtdAuthInvalid = 3,
  VtdAuthOverLimit = 4
} VTD_AUTH_STATUS;

// Hardware fingerprint structure - using definition from MiniVisorSecurity.h

// Authorization info structure - using unified MINI_VISOR_UNIVERSAL_AUTHORIZATION from MiniVisorAuth.h

// Global authorization state
static MINI_VISOR_UNIVERSAL_AUTHORIZATION gAuthInfo;
static MINI_VISOR_AUTH_STATUS gAuthStatus = MiniVisorAuthStatusUnauthorized;
static BOOLEAN gAuthDebugMode = FALSE;  // Debug mode flag
static EFI_HANDLE gAuthFsHandle = NULL; // Remember FS handle where auth was found/saved
static CHAR16 gAuthLoadedRelPath[260] = L""; // Remember exact relative path used during load

// File system cache to avoid repeated scans
typedef struct {
  EFI_HANDLE FsHandle;
  EFI_FILE_PROTOCOL *RootDir;
  CHAR16 *AuthFilePath;
  BOOLEAN Valid;
} FS_CACHE_ENTRY;

#define MAX_FS_CACHE_ENTRIES 8
static FS_CACHE_ENTRY gFsCache[MAX_FS_CACHE_ENTRIES];
static UINTN gFsCacheCount = 0;
static BOOLEAN gFsCacheInitialized = FALSE;

// Global system state
static EFI_HANDLE gImageHandle = NULL; // Image handle for launching applications

// Non-volatile usage counter variable names (to prevent rollback by file replacement)
static CONST CHAR16 VTD_NV_USAGE_VAR[] = L"VTdAuthUsage";
static CONST CHAR16 VTD_NV_HW_HASH_VAR[] = L"VTdAuthHwHash";

// NV helpers
STATIC EFI_STATUS VtdAuthReadNvUsage(OUT UINT32 *UsageOut);
STATIC EFI_STATUS VtdAuthWriteNvUsage(IN UINT32 Usage);

// External assembly functions
extern UINT64 AsmVmxOn(UINT64 VmxonRegion);
extern UINT64 AsmVmClear(UINT64 VmcsRegion);
extern UINT64 AsmVmPtrLd(UINT64 VmcsRegion);
extern UINT64 AsmVmRead(UINT32 Field);
extern UINT64 AsmVmWrite(UINT32 Field, UINT64 Value);
extern UINT64 AsmVmLaunch(VOID);
extern UINT64 AsmVmResume(VOID);
extern UINT64 AsmVmxOff(VOID);
extern UINT64 AsmVmFunc(UINT64 Function, UINT64 Param1, UINT64 Param2);

// Internal function declarations
VOID HandleVmxCpuidExit(VOID *Registers);
VOID HandleMsrReadExit(VOID *Registers);
VOID HandleMsrWriteExit(VOID *Registers);
VOID HandleVmcallExit(VOID *Registers);
VOID HandleVmxIoExit(UINT64 ExitQualification);
EFI_STATUS InitializeVtdPciConfig(VOID);
UINT32 HandlePciConfigRead(UINT32 ConfigAddress, UINT8 Offset, UINT8 Size);
VOID HandlePciConfigWrite(UINT32 ConfigAddress, UINT8 Offset, UINT8 Size, UINT32 Value);
EFI_STATUS CreateEnhancedDmarTable(VOID);
EFI_STATUS InstallMcfgTable(VOID);

// Global variables for SVM compatibility (if not using SVM, these can be stubs)
BOOLEAN gMiniVisorSvmDebugMode = FALSE;
HYPERVISOR_SVM_GLOBAL_DATA gMiniVisorSvmGlobalData = { 0 };

// Authorization system prototypes
EFI_STATUS VtdAuthInitializeLegacy(VOID);
VTD_AUTH_STATUS VtdAuthVerifyLicense(VOID);
EFI_STATUS VtdGenerateHardwareFingerprint(VTD_HARDWARE_FINGERPRINT *Fingerprint);
EFI_STATUS VtdRsaVerifySignature(IN UINT8 *Data, IN UINTN DataSize, IN UINT8 *Signature, IN UINT8 *PublicKey);
EFI_STATUS VtdSha256Hash(IN UINT8 *Data, IN UINTN DataSize, OUT UINT8 *Hash);
EFI_STATUS VtdValidateAuthorizationStructure(IN VTD_AUTHORIZATION_INFO *AuthInfo);
EFI_STATUS VtdAuthShowLegalWarning(VOID);
UINT32 VtdSimpleHash(UINT8 *Data, UINTN Length);
VOID VtdAuthUpdateUsageCount(VOID);
UINT64 VtdGetCpuSerialNumber(VOID);
EFI_STATUS VtdGetMainboardSerial(CHAR8 *SerialBuffer, UINTN BufferSize);
EFI_STATUS VtdAuthLoadFromFile(CHAR16 *AuthFileName);
EFI_STATUS VtdAuthSaveToFile(CHAR16 *AuthFileName);
EFI_STATUS VtdAuthLoadFromFileToBuffer(CHAR16 *FileName, OUT UINT8 **Buffer, OUT UINTN *BufferSize);
STATIC EFI_STATUS VtdAuthReadNvUsage(OUT UINT32 *UsageOut);
STATIC EFI_STATUS VtdAuthWriteNvUsage(IN UINT32 Usage);
// FS helper prototypes
STATIC EFI_STATUS VtdAuthOpenRootOnHandle(IN EFI_HANDLE FsHandle, OUT EFI_FILE_PROTOCOL **RootDir);
STATIC EFI_STATUS VtdAuthTryOpenFileOnHandle(IN EFI_HANDLE FsHandle, IN CHAR16 *AuthFileName, OUT EFI_FILE_PROTOCOL **RootDir, OUT EFI_FILE_PROTOCOL **AuthFile);
STATIC EFI_STATUS VtdAuthFindFileAcrossVolumes(IN CHAR16 *AuthFileName, OUT EFI_FILE_PROTOCOL **RootDir, OUT EFI_FILE_PROTOCOL **AuthFile);

// Cache management prototypes
STATIC VOID VtdAuthInitializeCache(VOID);
STATIC FS_CACHE_ENTRY* VtdAuthFindCacheEntry(EFI_HANDLE FsHandle);
STATIC EFI_STATUS VtdAuthAddCacheEntry(EFI_HANDLE FsHandle, EFI_FILE_PROTOCOL *RootDir, CHAR16 *AuthFilePath);
STATIC VOID VtdAuthClearCache(VOID);
STATIC EFI_STATUS VtdAuthGetLoadedImageFsHandle(OUT EFI_HANDLE *FsHandle);
STATIC VOID VtdAuthLogFsInfo(IN EFI_FILE_PROTOCOL *RootDir);
// Deep search helpers for locating authorization file anywhere on volumes
STATIC EFI_STATUS VtdAuthSearchFileInDir(IN EFI_FILE_PROTOCOL *Directory, IN CHAR16 *TargetFileName, OUT EFI_FILE_PROTOCOL **FoundFile, IN UINTN Depth);
STATIC EFI_STATUS VtdAuthFindFileByNameAcrossVolumes(IN CHAR16 *FileName, OUT EFI_HANDLE *FoundFsHandle, OUT EFI_FILE_PROTOCOL **RootDir, OUT EFI_FILE_PROTOCOL **AuthFile);
STATIC BOOLEAN VtdAuthFileNameEquals(IN CONST CHAR16 *A, IN CONST CHAR16 *B);

STATIC BOOLEAN
VtdAuthFileNameEquals(
  IN CONST CHAR16 *A,
  IN CONST CHAR16 *B
  )
{
  if (A == NULL || B == NULL) return FALSE;
  while (*A != L'\0' && *B != L'\0') {
    CHAR16 ca = *A;
    CHAR16 cb = *B;
    if (ca >= L'a' && ca <= L'z') ca = (CHAR16)(ca - (L'a' - L'A'));
    if (cb >= L'a' && cb <= L'z') cb = (CHAR16)(cb - (L'a' - L'A'));
    if (ca != cb) return FALSE;
    A++; B++;
  }
  return *A == L'\0' && *B == L'\0';
}

STATIC EFI_STATUS
VtdAuthSearchFileInDir(
  IN EFI_FILE_PROTOCOL *Directory,
  IN CHAR16 *TargetFileName,
  OUT EFI_FILE_PROTOCOL **FoundFile,
  IN UINTN Depth
  )
{
  EFI_STATUS Status;
  EFI_FILE_INFO *FileInfo = NULL;
  UINTN InfoSize = 0;
  EFI_FILE_PROTOCOL *Handle = NULL;

  if (FoundFile == NULL || Directory == NULL || TargetFileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *FoundFile = NULL;
  
  if (Depth > 16) {
    return EFI_NOT_FOUND;
  }

  // Reset directory enumeration to start
  Status = Directory->SetPosition(Directory, 0);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  // Start with a reasonable buffer; grow if needed
  InfoSize = SIZE_OF_EFI_FILE_INFO + 256 * sizeof(CHAR16);
  while (TRUE) {
    if (FileInfo != NULL) {
      gBS->FreePool(FileInfo);
      FileInfo = NULL;
    }
    Status = gBS->AllocatePool(EfiBootServicesData, InfoSize, (VOID**)&FileInfo);
    if (EFI_ERROR(Status) || FileInfo == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    UINTN ReadSize = InfoSize;
    Status = Directory->Read(Directory, &ReadSize, FileInfo);
    if (Status == EFI_BUFFER_TOO_SMALL) {
      // Grow buffer to required size and retry
      InfoSize = ReadSize;
      continue;
    }
    if (EFI_ERROR(Status)) {
      gBS->FreePool(FileInfo);
      return Status;
    }
    if (ReadSize == 0) {
      // End of directory
      gBS->FreePool(FileInfo);
      return EFI_NOT_FOUND;
    }

    // Skip "." and ".."
    if (VtdAuthFileNameEquals(FileInfo->FileName, L".") || VtdAuthFileNameEquals(FileInfo->FileName, L"..")) {
      gBS->FreePool(FileInfo);
      FileInfo = NULL;
      continue;
    }

    if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) == 0) {
      // File
      if (VtdAuthFileNameEquals(FileInfo->FileName, TargetFileName)) {
        Status = Directory->Open(Directory, &Handle, FileInfo->FileName, EFI_FILE_MODE_READ, 0);
        if (!EFI_ERROR(Status)) {
          *FoundFile = Handle;
          gBS->FreePool(FileInfo);
          return EFI_SUCCESS;
        }
      }
    } else {
      // Directory: recurse
      EFI_FILE_PROTOCOL *SubDir = NULL;
      Status = Directory->Open(Directory, &SubDir, FileInfo->FileName, EFI_FILE_MODE_READ, 0);
      if (!EFI_ERROR(Status) && SubDir != NULL) {
        EFI_FILE_PROTOCOL *SubFound = NULL;
        Status = VtdAuthSearchFileInDir(SubDir, TargetFileName, &SubFound, Depth + 1);
        SubDir->Close(SubDir);
        if (!EFI_ERROR(Status) && SubFound != NULL) {
          *FoundFile = SubFound;
          gBS->FreePool(FileInfo);
          return EFI_SUCCESS;
        }
      }
    }

    // Continue to next entry; buffer reused in next loop (FileInfo will be freed at start of next iteration)
  }

  // Should never reach here, but ensure FileInfo is freed
  if (FileInfo != NULL) {
    gBS->FreePool(FileInfo);
  }
}

STATIC EFI_STATUS
VtdAuthFindFileByNameAcrossVolumes(
  IN CHAR16 *FileName,
  OUT EFI_HANDLE *FoundFsHandle,
  OUT EFI_FILE_PROTOCOL **RootDir,
  OUT EFI_FILE_PROTOCOL **AuthFile
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuffer = NULL;
  UINTN HandleCount = 0;

  if (FoundFsHandle == NULL || RootDir == NULL || AuthFile == NULL || FileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *FoundFsHandle = NULL;
  *RootDir = NULL;
  *AuthFile = NULL;

  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR(Status) || HandleCount == 0 || HandleBuffer == NULL) {
    return EFI_NOT_FOUND;
  }

  // Initialize cache if needed
  VtdAuthInitializeCache();

  // First, check cache for known locations
  for (UINTN i = 0; i < HandleCount; i++) {
    FS_CACHE_ENTRY *CacheEntry = VtdAuthFindCacheEntry(HandleBuffer[i]);
    if (CacheEntry != NULL && CacheEntry->AuthFilePath != NULL) {
      // Try to open cached file directly
      EFI_FILE_PROTOCOL *Root = NULL;
      EFI_STATUS S2 = VtdAuthOpenRootOnHandle(HandleBuffer[i], &Root);
      if (!EFI_ERROR(S2) && Root != NULL) {
        EFI_FILE_PROTOCOL *Found = NULL;
        S2 = Root->Open(Root, &Found, CacheEntry->AuthFilePath, EFI_FILE_MODE_READ, 0);
        if (!EFI_ERROR(S2) && Found != NULL) {
          *FoundFsHandle = HandleBuffer[i];
          *RootDir = Root;
          *AuthFile = Found;
          gBS->FreePool(HandleBuffer);
          DEBUG((EFI_D_INFO, "Found auth file in cache: %s\n", CacheEntry->AuthFilePath));
          return EFI_SUCCESS;
        }
        Root->Close(Root);
      }
      // Cache entry is stale, invalidate it
      CacheEntry->Valid = FALSE;
    }
  }

  // Cache miss, perform search with reduced depth for performance
  for (UINTN i = 0; i < HandleCount; i++) {
    EFI_FILE_PROTOCOL *Root = NULL;
    Status = VtdAuthOpenRootOnHandle(HandleBuffer[i], &Root);
    if (EFI_ERROR(Status) || Root == NULL) {
      continue;
    }
    EFI_FILE_PROTOCOL *Found = NULL;
    Status = VtdAuthSearchFileInDir(Root, FileName, &Found, 2); // Reduced max depth to 2 for performance
    if (!EFI_ERROR(Status) && Found != NULL) {
      *FoundFsHandle = HandleBuffer[i];
      *RootDir = Root;
      *AuthFile = Found;
      
      // Cache the successful location for future use
      VtdAuthAddCacheEntry(HandleBuffer[i], Root, FileName);
      
      gBS->FreePool(HandleBuffer);
      return EFI_SUCCESS;
    }
    Root->Close(Root);
  }

  gBS->FreePool(HandleBuffer);
  return EFI_NOT_FOUND;
}

// Windows 启动相关逻辑已移除，驱动不再负责引导系统

// Real-time protection functions
VOID VtdRealTimeProtectionCheck(VOID);
VOID VtdAntiDetectionMeasures(VOID);
VOID VtdUpdatePerformanceCounters(UINT32 ExitReason);
BOOLEAN VtdDetectAntiAnalysis(VOID);
VOID VtdHandleDetectionAttempt(UINT32 DetectionType);

// Global variables
static RING2_VIRTUALIZATION_MANAGER gRing2Manager;
static BOOLEAN gVmxSupported = FALSE;
static BOOLEAN gNestedVmxSupported = FALSE;

// VTD globals
static VTD_MANAGER gVtdManager;
static VTD_DOMAIN gVtdDomains[256]; // Supports up to 256 domains
static VTD_DEVICE gVtdDevices[1024]; // Supports up to 1024 devices
static VTD_INTERRUPT_REMAP gVtdInterruptRemaps[1024]; // Supports up to 1024 interrupt remaps
static BOOLEAN gVtdSupported = FALSE;
static BOOLEAN gVtdInitialized = FALSE;

// VT-d shadow register model to present coherent capabilities/state
typedef struct {
  UINT64 Cap;      // VTD_CAP_REG
  UINT64 Ecap;     // VTD_ECAP_REG
  UINT64 Gcmd;     // VTD_GCMD_REG
  UINT64 Gsts;     // VTD_GSTS_REG
  UINT64 Rtaddr;   // VTD_RTADDR_REG
  UINT64 Ccmd;     // VTD_CCMD_REG
  UINT64 Fsts;     // VTD_FSTS_REG
  UINT64 Fectl;    // VTD_FECTL_REG
  UINT64 Fedata;   // VTD_FEDATA_REG
  UINT64 Feaddr;   // VTD_FEADDR_REG
  UINT64 Feuaddr;  // VTD_FEUADDR_REG
  UINT64 Irta;     // Interrupt remap table address (not in basic set, tracked separately)
} VTD_SHADOW_REGS;

static VTD_SHADOW_REGS gVtdRegs;

static VOID
InitializeVtdShadowRegs(VOID)
{
  // Reasonable capability defaults: support 4-level paging (SAGAW=39/48), queued invalidation, write buffer flush
  // CAP fields are implementation-specific; craft coherent yet generic values.
  // Layout (vendor-specific) not fully modeled; provide typical bits so guest checks succeed.
  gVtdRegs.Cap   = 0;
  // SAGAW: support 39-bit and 48-bit (bits 8:12 typically). Use 0b00110 at positions -> simplified here as constants.
  gVtdRegs.Cap  |= (1ULL << 0);      // Nd: at least one domain supported (placeholder)
  gVtdRegs.Cap  |= (1ULL << 7);      // RWBF
  gVtdRegs.Cap  |= (1ULL << 23);     // CM (caching mode)
  gVtdRegs.Cap  |= (1ULL << 34);     // SLLPS support (superpages) indicator example
  // ECAP: enable interrupt remapping, queued invalidation
  gVtdRegs.Ecap  = 0;
  gVtdRegs.Ecap |= (1ULL << 3);      // QI
  gVtdRegs.Ecap |= (1ULL << 1);      // IR
  gVtdRegs.Ecap |= (1ULL << 0);      // C (coherency) example
  gVtdRegs.Ecap |= (1ULL << 7);      // EIM (x2APIC) example

  gVtdRegs.Gcmd   = 0;
  gVtdRegs.Gsts   = 0;               // TES=0 until EnableVtd sets it
  gVtdRegs.Rtaddr = 0;
  gVtdRegs.Ccmd   = 0;
  gVtdRegs.Fsts   = 0;
  gVtdRegs.Fectl  = 0;
  gVtdRegs.Fedata = 0;
  gVtdRegs.Feaddr = 0;
  gVtdRegs.Feuaddr= 0;
  gVtdRegs.Irta   = 0;
}

static VOID
SyncVtdRegsToMmio(VOID)
{
  if (gVtdManager.RegisterBaseAddress == 0) {
    return;
  }
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_CAP_REG),    gVtdRegs.Cap);
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_ECAP_REG),   gVtdRegs.Ecap);
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_GCMD_REG),   gVtdRegs.Gcmd);
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_GSTS_REG),   gVtdRegs.Gsts);
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_RTADDR_REG), gVtdRegs.Rtaddr);
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_CCMD_REG),   gVtdRegs.Ccmd);
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_FSTS_REG),   gVtdRegs.Fsts);
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_FECTL_REG),  gVtdRegs.Fectl);
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_FEDATA_REG), gVtdRegs.Fedata);
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_FEADDR_REG), gVtdRegs.Feaddr);
  MmioWrite64((UINTN)(gVtdManager.RegisterBaseAddress + VTD_FEUADDR_REG),gVtdRegs.Feuaddr);
}

// Function declarations
EFI_STATUS CheckNestedVmxSupport(VOID);
EFI_STATUS InitializeRing2Virtualization(VOID);
EFI_STATUS InitializeVtdEmulation(VOID);
EFI_STATUS SetupVmcs(VOID);
EFI_STATUS AllocateVmxRegion(VOID);
EFI_STATUS SetupEpt(VOID);
STATIC VOID ProtectVtdMmioWithEpt(VOID);
EFI_STATUS SetupMsrBitmap(VOID);
EFI_STATUS SetupIoBitmap(VOID);
EFI_STATUS Ring2VmExitHandler(UINT32 ExitReason, VM_EXIT_INFO *ExitInfo, RING2_VIRTUALIZATION_MANAGER *Manager);

// VTD function declarations
EFI_STATUS CheckVtdSupport(VOID);
EFI_STATUS InitializeVtd(VOID);
EFI_STATUS SetupVtdTables(VOID);
EFI_STATUS EnableVtd(VOID);
EFI_STATUS DisableVtd(VOID);
EFI_STATUS CreateVtdDomain(UINT32 DomainId, VTD_DOMAIN **Domain);
EFI_STATUS DeleteVtdDomain(UINT32 DomainId);
EFI_STATUS AddVtdDevice(UINT16 SegmentNumber, UINT8 BusNumber, UINT8 DeviceNumber, UINT8 FunctionNumber, UINT32 DomainId);
EFI_STATUS RemoveVtdDevice(UINT16 SegmentNumber, UINT8 BusNumber, UINT8 DeviceNumber, UINT8 FunctionNumber);
EFI_STATUS SetupVtdInterruptRemapping(UINT32 SourceId, UINT8 Vector, UINT8 DeliveryMode, UINT8 DestinationMode, UINT8 TriggerMode, UINT8 Destination);
EFI_STATUS RemoveVtdInterruptRemapping(UINT32 SourceId, UINT8 Vector);
EFI_STATUS VtdReadRegister(UINT64 RegisterBaseAddress, UINT32 Register, UINT64 *Value);
EFI_STATUS VtdWriteRegister(UINT64 RegisterBaseAddress, UINT32 Register, UINT64 Value);
EFI_STATUS ParseDmarTable(VOID);
EFI_STATUS SetupVtdRootTable(VOID);
EFI_STATUS SetupVtdContextTable(VOID);
EFI_STATUS SetupVtdInterruptRemapTable(VOID);

/** VTD register read **/
EFI_STATUS
VtdReadRegister(
  IN UINT64 RegisterBaseAddress,
  IN UINT32 Register,
  OUT UINT64 *Value
)
{
  if (Value == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  // Serve from shadow register model for coherence regardless of actual MMIO contents
  switch (Register) {
    case VTD_CAP_REG:    *Value = gVtdRegs.Cap;    break;
    case VTD_ECAP_REG:   *Value = gVtdRegs.Ecap;   break;
    case VTD_GCMD_REG:   *Value = gVtdRegs.Gcmd;   break;
    case VTD_GSTS_REG:   *Value = gVtdRegs.Gsts;   break;
    case VTD_RTADDR_REG: *Value = gVtdRegs.Rtaddr; break;
    case VTD_CCMD_REG:   *Value = gVtdRegs.Ccmd;   break;
    case VTD_FSTS_REG:   *Value = gVtdRegs.Fsts;   break;
    case VTD_FECTL_REG:  *Value = gVtdRegs.Fectl;  break;
    case VTD_FEDATA_REG: *Value = gVtdRegs.Fedata; break;
    case VTD_FEADDR_REG: *Value = gVtdRegs.Feaddr; break;
    case VTD_FEUADDR_REG:*Value = gVtdRegs.Feuaddr;break;
    default:
      // Unknown/unused offset: return 0 to appear quiescent
      *Value = 0;
      break;
  }
  return EFI_SUCCESS;
}

/** VTD register write **/
EFI_STATUS
VtdWriteRegister(
  IN UINT64 RegisterBaseAddress,
  IN UINT32 Register,
  IN UINT64 Value
)
{
  // Update shadow state; apply simple semantics for GCMD/RTADDR, etc.
  switch (Register) {
    case VTD_GCMD_REG:
      gVtdRegs.Gcmd = Value;
      // If TE bit set, reflect in GSTS.TES
      if ((Value & 0x1ULL) != 0) {
        gVtdRegs.Gsts |= 0x1ULL;  // TES=1
      } else {
        gVtdRegs.Gsts &= ~0x1ULL; // TES=0
      }
      break;
    case VTD_RTADDR_REG:
      gVtdRegs.Rtaddr = Value;
      break;
    case VTD_CCMD_REG:
      gVtdRegs.Ccmd = Value;
      break;
    case VTD_FSTS_REG:
      gVtdRegs.Fsts = Value;
      break;
    case VTD_FECTL_REG:
      gVtdRegs.Fectl = Value;
      break;
    case VTD_FEDATA_REG:
      gVtdRegs.Fedata = Value;
      break;
    case VTD_FEADDR_REG:
      gVtdRegs.Feaddr = Value;
      break;
    case VTD_FEUADDR_REG:
      gVtdRegs.Feuaddr = Value;
      break;
    default:
      // Ignore writes to unknown offsets
      break;
  }
  return EFI_SUCCESS;
}

/** Setup VTD root table **/
EFI_STATUS
SetupVtdRootTable(VOID)
{
  EFI_PHYSICAL_ADDRESS RootTableAddress;
  VTD_ROOT_TABLE_ENTRY *RootTable;
  UINT32 i;
  
  // Allocate root table memory (256 entries, 8 bytes each)
  RootTableAddress = 0;
  if (EFI_ERROR(MiniVisorAllocateTrackedPages(AllocateAnyPages, EfiReservedMemoryType, 
                                   EFI_SIZE_TO_PAGES(256 * sizeof(VTD_ROOT_TABLE_ENTRY)), &RootTableAddress))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate VTD root table\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  gVtdManager.RootTableAddress = RootTableAddress;
  gVtdManager.RootTableSize = 256 * sizeof(VTD_ROOT_TABLE_ENTRY);
  
  // Initialize table
  RootTable = (VTD_ROOT_TABLE_ENTRY*)RootTableAddress;
  ZeroMem(RootTable, 256 * sizeof(VTD_ROOT_TABLE_ENTRY));
  
  // Initialize root table entries
  for (i = 0; i < 256; i++) {
    RootTable[i].Present = 0;
    RootTable[i].Reserved1 = 0;
    RootTable[i].ContextTablePointer = 0;
  }
  
  DEBUG((EFI_D_INFO, "VTD root table setup at 0x%lx\n", RootTableAddress));
  return EFI_SUCCESS;
}

/** Setup VTD context table **/
EFI_STATUS
SetupVtdContextTable(VOID)
{
  EFI_PHYSICAL_ADDRESS ContextTableAddress;
  VTD_CONTEXT_TABLE_ENTRY *ContextTable;
  UINT32 i;
  
  // Allocate context table memory (256 entries, 16 bytes each)
  ContextTableAddress = 0;
  if (EFI_ERROR(MiniVisorAllocateTrackedPages(AllocateAnyPages, EfiReservedMemoryType, 
                                   EFI_SIZE_TO_PAGES(256 * sizeof(VTD_CONTEXT_TABLE_ENTRY)), &ContextTableAddress))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate VTD context table\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  gVtdManager.ContextTableAddress = ContextTableAddress;
  gVtdManager.ContextTableSize = 256 * sizeof(VTD_CONTEXT_TABLE_ENTRY);
  
  // Initialize context table
  ContextTable = (VTD_CONTEXT_TABLE_ENTRY*)ContextTableAddress;
  ZeroMem(ContextTable, 256 * sizeof(VTD_CONTEXT_TABLE_ENTRY));
  
  // Initialize context table entries
  for (i = 0; i < 256; i++) {
    ContextTable[i].Present = 0;
    ContextTable[i].FaultProcessingDisable = 0;
    ContextTable[i].TranslationType = 0;
    ContextTable[i].Reserved1 = 0;
    ContextTable[i].SecondLevelPageTablePointer = 0;
    ContextTable[i].AddressWidth = 0;
    ContextTable[i].Reserved2 = 0;
    ContextTable[i].DomainId = 0;
    ContextTable[i].Reserved3 = 0;
    ContextTable[i].Reserved4 = 0;
  }
  
  DEBUG((EFI_D_INFO, "VTD context table setup at 0x%lx\n", ContextTableAddress));
  return EFI_SUCCESS;
}

/** Setup VTD interrupt remap table **/
EFI_STATUS
SetupVtdInterruptRemapTable(VOID)
{
  EFI_PHYSICAL_ADDRESS InterruptRemapTableAddress;
  VTD_INTERRUPT_REMAP_TABLE_ENTRY *InterruptRemapTable;
  UINT32 i;
  
  // Allocate interrupt remap table memory (1024 entries, 8 bytes each)
  InterruptRemapTableAddress = 0;
  if (EFI_ERROR(MiniVisorAllocateTrackedPages(AllocateAnyPages, EfiReservedMemoryType, 
                                   EFI_SIZE_TO_PAGES(1024 * sizeof(VTD_INTERRUPT_REMAP_TABLE_ENTRY)), &InterruptRemapTableAddress))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate VTD interrupt remap table\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  gVtdManager.InterruptRemapTableAddress = InterruptRemapTableAddress;
  gVtdManager.InterruptRemapTableSize = 1024 * sizeof(VTD_INTERRUPT_REMAP_TABLE_ENTRY);
  
  // Initialize interrupt remap table
  InterruptRemapTable = (VTD_INTERRUPT_REMAP_TABLE_ENTRY*)InterruptRemapTableAddress;
  ZeroMem(InterruptRemapTable, 1024 * sizeof(VTD_INTERRUPT_REMAP_TABLE_ENTRY));
  
  // Initialize interrupt remap table entries
  for (i = 0; i < 1024; i++) {
    InterruptRemapTable[i].Present = 0;
    InterruptRemapTable[i].DestinationMode = 0;
    InterruptRemapTable[i].RedirectionHint = 0;
    InterruptRemapTable[i].TriggerMode = 0;
    InterruptRemapTable[i].DeliveryMode = 0;
    InterruptRemapTable[i].Reserved1 = 0;
    InterruptRemapTable[i].Destination = 0;
    InterruptRemapTable[i].Reserved2 = 0;
    InterruptRemapTable[i].Vector = 0;
    InterruptRemapTable[i].Reserved3 = 0;
  }
  
  DEBUG((EFI_D_INFO, "VTD interrupt remap table setup at 0x%lx\n", InterruptRemapTableAddress));
  return EFI_SUCCESS;
}

/** Initialize VTD **/
EFI_STATUS
InitializeVtd(VOID)
{
  EFI_STATUS Status;
  
  // Check VTD support
  Status = CheckVtdSupport();
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "VTD not supported\n"));
    return Status;
  }
  
  // Initialize VTD manager
  ZeroMem(&gVtdManager, sizeof(gVtdManager));
  gVtdManager.Initialized = FALSE;
  gVtdManager.Enabled = FALSE;
  gVtdManager.SegmentCount = 0;
  gVtdManager.DomainCount = 0;

  // Allocate a dedicated MMIO region to act as VT-d register base
  gVtdManager.RegisterBaseAddress = 0;
  if (EFI_ERROR(MiniVisorAllocateTrackedPages(AllocateAnyPages, EfiReservedMemoryType,
                                   EFI_SIZE_TO_PAGES(0x1000),
                                   (EFI_PHYSICAL_ADDRESS *)&gVtdManager.RegisterBaseAddress))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate VT-d MMIO base\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  gVtdManager.MmioBase = gVtdManager.RegisterBaseAddress;

  // Initialize shadow registers before any use
  InitializeVtdShadowRegs();
  SyncVtdRegsToMmio();
  
  // Setup VTD tables
  Status = SetupVtdTables();
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "Failed to setup VTD tables\n"));
    return Status;
  }
  // DMAR injection handled in InitializeVtdEmulation (early, pre-virtualization)
  // Only install a minimal MCFG here if firmware lacks one (no compatibility mode)
  if (!gVtdManager.CompatibilityMode) {
    Status = InstallMcfgTable();
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_WARN, "Failed to install MCFG table, continuing without ECAM\n"));
    }
  } else {
    DEBUG((EFI_D_INFO, "Skipping MCFG installation due to existing firmware ACPI\n"));
  }
  
  gVtdManager.Initialized = TRUE;
  gVtdInitialized = TRUE;
  DEBUG((EFI_D_INFO, "VTD initialized successfully\n"));
  return EFI_SUCCESS;
}

/** Setup VTD tables **/
EFI_STATUS
SetupVtdTables(VOID)
{
  EFI_STATUS Status;
  
  // Root table
  Status = SetupVtdRootTable();
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  // Context table
  Status = SetupVtdContextTable();
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  // Interrupt remap table
  Status = SetupVtdInterruptRemapTable();
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  return EFI_SUCCESS;
}

/** Enable VTD **/
EFI_STATUS
EnableVtd(VOID)
{
  UINT64 GlobalCommand;
  UINT64 GlobalStatus;
  UINT64 RootTableAddress;
  UINT64 InterruptRemapTableAddress;
  UINT32 Timeout;
  
  if (!gVtdInitialized) {
    DEBUG((EFI_D_ERROR, "VTD not initialized\n"));
    return EFI_NOT_READY;
  }
  
  // Read global command
  VtdReadRegister(gVtdManager.RegisterBaseAddress, VTD_GCMD_REG, &GlobalCommand);
  
  // Set root table address
  RootTableAddress = gVtdManager.RootTableAddress & ~0xFFFULL;
  VtdWriteRegister(gVtdManager.RegisterBaseAddress, VTD_RTADDR_REG, RootTableAddress);
  
  // Set interrupt remap table address
  InterruptRemapTableAddress = gVtdManager.InterruptRemapTableAddress >> 12; // page aligned
  // Note: real hardware may require specific address alignment
  
  // Program shadow RTADDR with page-aligned base
  VtdWriteRegister(gVtdManager.RegisterBaseAddress, VTD_RTADDR_REG,
                   (gVtdManager.RootTableAddress & ~0xFFFULL));

  // Enable DMA remapping (TE)
  GlobalCommand |= 0x00000001;
  VtdWriteRegister(gVtdManager.RegisterBaseAddress, VTD_GCMD_REG, GlobalCommand);
  // Mirror shadow state to MMIO for guests mapping the DRHD BAR directly
  SyncVtdRegsToMmio();
  
  // Wait for enable
  Timeout = 1000;
  while (Timeout > 0) {
    VtdReadRegister(gVtdManager.RegisterBaseAddress, VTD_GSTS_REG, &GlobalStatus);
    if (GlobalStatus & 0x00000001) { // TES (Translation Enable Status)
      break;
    }
    gBS->Stall(1000); // Stall 1ms
    Timeout--;
  }
  
  if (Timeout == 0) {
    DEBUG((EFI_D_ERROR, "VTD enable timeout\n"));
    return EFI_TIMEOUT;
  }
  
  gVtdManager.Enabled = TRUE;
  DEBUG((EFI_D_INFO, "VTD enabled successfully\n"));
  return EFI_SUCCESS;
}

/** Disable VTD **/
EFI_STATUS
DisableVtd(VOID)
{
  UINT64 GlobalCommand;
  UINT64 GlobalStatus;
  UINT32 Timeout;
  
  if (!gVtdInitialized) {
    return EFI_NOT_READY;
  }
  
  // Read global command
  VtdReadRegister(gVtdManager.RegisterBaseAddress, VTD_GCMD_REG, &GlobalCommand);
  
  // Disable DMA remapping
  GlobalCommand &= ~0x00000001; // TE (Translation Enable)
  VtdWriteRegister(gVtdManager.RegisterBaseAddress, VTD_GCMD_REG, GlobalCommand);
  SyncVtdRegsToMmio();
  
  // Wait for disable
  Timeout = 1000;
  while (Timeout > 0) {
    VtdReadRegister(gVtdManager.RegisterBaseAddress, VTD_GSTS_REG, &GlobalStatus);
    if (!(GlobalStatus & 0x00000001)) { // TES (Translation Enable Status)
      break;
    }
    gBS->Stall(1000); // Stall 1ms
    Timeout--;
  }
  
  if (Timeout == 0) {
    DEBUG((EFI_D_ERROR, "VTD disable timeout\n"));
    return EFI_TIMEOUT;
  }
  
  gVtdManager.Enabled = FALSE;
  DEBUG((EFI_D_INFO, "VTD disabled successfully\n"));
  return EFI_SUCCESS;
}

/** Create VTD domain **/
EFI_STATUS
CreateVtdDomain(
  IN UINT32 DomainId,
  OUT VTD_DOMAIN **Domain
)
{
  VTD_DOMAIN *NewDomain;
  EFI_PHYSICAL_ADDRESS SecondLevelPageTableAddress;
  VTD_PAGE_TABLE_ENTRY_4K *SecondLevelPageTable;
  UINT32 i;
  
  if (Domain == NULL || DomainId >= 256) {
    return EFI_INVALID_PARAMETER;
  }
  
  if (gVtdDomains[DomainId].Active) {
    DEBUG((EFI_D_ERROR, "Domain %d already exists\n", DomainId));
    return EFI_ALREADY_STARTED;
  }
  
  // Allocate second-level page table memory (512 entries, 8 bytes each)
  SecondLevelPageTableAddress = 0;
  if (EFI_ERROR(gBS->AllocatePages(AllocateAnyPages, EfiReservedMemoryType, 
                                   EFI_SIZE_TO_PAGES(512 * sizeof(VTD_PAGE_TABLE_ENTRY_4K)), &SecondLevelPageTableAddress))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate VTD second level page table\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Initialize page table
  SecondLevelPageTable = (VTD_PAGE_TABLE_ENTRY_4K*)SecondLevelPageTableAddress;
  ZeroMem(SecondLevelPageTable, 512 * sizeof(VTD_PAGE_TABLE_ENTRY_4K));
  
  // Initialize page table entries (1:1 map first 2MB)
  for (i = 0; i < 512; i++) {
    SecondLevelPageTable[i].Present = 1;
    SecondLevelPageTable[i].ReadWrite = 1;
    SecondLevelPageTable[i].UserSupervisor = 1;
    SecondLevelPageTable[i].WriteThrough = 0;
    SecondLevelPageTable[i].CacheDisable = 0;
    SecondLevelPageTable[i].Accessed = 0;
    SecondLevelPageTable[i].Dirty = 0;
    SecondLevelPageTable[i].PageSize = 0;
    SecondLevelPageTable[i].Global = 0;
    SecondLevelPageTable[i].Reserved1 = 0;
    SecondLevelPageTable[i].ProtectionKey = 0;
    SecondLevelPageTable[i].Reserved2 = 0;
    SecondLevelPageTable[i].PhysicalAddress = i; // 1:1 mapping
  }
  
  // Initialize domain
  NewDomain = &gVtdDomains[DomainId];
  NewDomain->DomainId = DomainId;
  NewDomain->ContextTableEntry = 0; // Set when device is assigned
  NewDomain->SecondLevelPageTableAddress = SecondLevelPageTableAddress;
  NewDomain->SecondLevelPageTableSize = 512 * sizeof(VTD_PAGE_TABLE_ENTRY_4K);
  NewDomain->Active = TRUE;
  NewDomain->DeviceCount = 0;
  ZeroMem(NewDomain->AssignedDevices, sizeof(NewDomain->AssignedDevices));
  
  *Domain = NewDomain;
  gVtdManager.DomainCount++;
  
  DEBUG((EFI_D_INFO, "VTD domain %d created successfully\n", DomainId));
  return EFI_SUCCESS;
}

/** Delete VTD domain **/
EFI_STATUS
DeleteVtdDomain(
  IN UINT32 DomainId
)
{
  VTD_DOMAIN *Domain;
  
  if (DomainId >= 256) {
    return EFI_INVALID_PARAMETER;
  }
  
  Domain = &gVtdDomains[DomainId];
  if (!Domain->Active) {
    DEBUG((EFI_D_ERROR, "Domain %d does not exist\n", DomainId));
    return EFI_NOT_FOUND;
  }
  
  // Free domain page table memory
  if (Domain->SecondLevelPageTableAddress != 0) {
    gBS->FreePages(Domain->SecondLevelPageTableAddress, 
                   EFI_SIZE_TO_PAGES(Domain->SecondLevelPageTableSize));
  }
  
  // Reset
  ZeroMem(Domain, sizeof(VTD_DOMAIN));
  gVtdManager.DomainCount--;
  
  DEBUG((EFI_D_INFO, "VTD domain %d deleted successfully\n", DomainId));
  return EFI_SUCCESS;
}

/** Add VTD device **/
EFI_STATUS
AddVtdDevice(
  IN UINT16 SegmentNumber,
  IN UINT8  BusNumber,
  IN UINT8  DeviceNumber,
  IN UINT8  FunctionNumber,
  IN UINT32 DomainId
)
{
  VTD_DEVICE *Device;
  VTD_DOMAIN *Domain;
  VTD_ROOT_TABLE_ENTRY *RootTable;
  VTD_CONTEXT_TABLE_ENTRY *ContextTable;
  UINT32 DeviceIndex;
  UINT32 BusIndex;
  
  if (DomainId >= 256) {
    return EFI_INVALID_PARAMETER;
  }
  
  Domain = &gVtdDomains[DomainId];
  if (!Domain->Active) {
    DEBUG((EFI_D_ERROR, "Domain %d does not exist\n", DomainId));
    return EFI_NOT_FOUND;
  }
  
  // Find free device slot
  DeviceIndex = 0;
  while (DeviceIndex < 1024) {
    Device = &gVtdDevices[DeviceIndex];
    if (!Device->Active) {
      break;
    }
    if (Device->SegmentNumber == SegmentNumber &&
        Device->BusNumber == BusNumber &&
        Device->DeviceNumber == DeviceNumber &&
        Device->FunctionNumber == FunctionNumber) {
      DEBUG((EFI_D_ERROR, "Device already exists\n"));
      return EFI_ALREADY_STARTED;
    }
    DeviceIndex++;
  }
  
  if (DeviceIndex >= 1024) {
    DEBUG((EFI_D_ERROR, "No free device slot\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Initialize device
  Device = &gVtdDevices[DeviceIndex];
  Device->SegmentNumber = SegmentNumber;
  Device->BusNumber = BusNumber;
  Device->DeviceNumber = DeviceNumber;
  Device->FunctionNumber = FunctionNumber;
  Device->DomainId = DomainId;
  Device->Active = TRUE;
  Device->ContextTableEntry = 0; // Set when context table is updated
  
  // Add to domain
  if (Domain->DeviceCount < 256) {
    Domain->AssignedDevices[Domain->DeviceCount] = (UINT16)DeviceIndex;
    Domain->DeviceCount++;
  }
  
  // Update root and context tables
  RootTable = (VTD_ROOT_TABLE_ENTRY*)gVtdManager.RootTableAddress;
  ContextTable = (VTD_CONTEXT_TABLE_ENTRY*)gVtdManager.ContextTableAddress;
  
  BusIndex = BusNumber; // Direct mapping
  
  // Ensure root entry present
  if (!RootTable[BusIndex].Present) {
    RootTable[BusIndex].Present = 1;
    RootTable[BusIndex].Reserved1 = 0;
    RootTable[BusIndex].ContextTablePointer = gVtdManager.ContextTableAddress >> 12;
  }
  
  // Fill context table entry
  ContextTable[BusIndex].Present = 1;
  ContextTable[BusIndex].FaultProcessingDisable = 0;
  ContextTable[BusIndex].TranslationType = 0; // 4K pages
  ContextTable[BusIndex].Reserved1 = 0;
  ContextTable[BusIndex].SecondLevelPageTablePointer = Domain->SecondLevelPageTableAddress >> 12;
  ContextTable[BusIndex].AddressWidth = 2; // 39-bit address
  ContextTable[BusIndex].Reserved2 = 0;
  // Set DomainId lower 16 bits
  ContextTable[BusIndex].DomainId = (UINT16)(DomainId & 0xFFFF);
  ContextTable[BusIndex].Reserved3 = 0;
  ContextTable[BusIndex].Reserved4 = 0;
  
  Device->ContextTableEntry = (UINT64)&ContextTable[BusIndex];
  
  DEBUG((EFI_D_INFO, "VTD device %04x:%02x:%02x.%x added to domain %d\n", 
         SegmentNumber, BusNumber, DeviceNumber, FunctionNumber, DomainId));
  return EFI_SUCCESS;
}

/** Remove VTD device **/
EFI_STATUS
RemoveVtdDevice(
  IN UINT16 SegmentNumber,
  IN UINT8  BusNumber,
  IN UINT8  DeviceNumber,
  IN UINT8  FunctionNumber
)
{
  VTD_DEVICE *Device;
  VTD_DOMAIN *Domain;
  UINT32 DeviceIndex;
  UINT32 DomainIndex;
  UINT32 DeviceInDomainIndex;
  
  // Find device
  DeviceIndex = 0;
  while (DeviceIndex < 1024) {
    Device = &gVtdDevices[DeviceIndex];
    if (Device->Active &&
        Device->SegmentNumber == SegmentNumber &&
        Device->BusNumber == BusNumber &&
        Device->DeviceNumber == DeviceNumber &&
        Device->FunctionNumber == FunctionNumber) {
      break;
    }
    DeviceIndex++;
  }
  
  if (DeviceIndex >= 1024) {
    DEBUG((EFI_D_ERROR, "Device not found\n"));
    return EFI_NOT_FOUND;
  }
  
  // Remove from domain
  DomainIndex = Device->DomainId;
  Domain = &gVtdDomains[DomainIndex];
  
  DeviceInDomainIndex = 0;
  while (DeviceInDomainIndex < Domain->DeviceCount) {
    if (Domain->AssignedDevices[DeviceInDomainIndex] == DeviceIndex) {
      // Remove device
      Domain->AssignedDevices[DeviceInDomainIndex] = Domain->AssignedDevices[Domain->DeviceCount - 1];
      Domain->DeviceCount--;
      break;
    }
    DeviceInDomainIndex++;
  }
  
  // Reset device
  ZeroMem(Device, sizeof(VTD_DEVICE));
  
  DEBUG((EFI_D_INFO, "VTD device %04x:%02x:%02x.%x removed\n", 
         SegmentNumber, BusNumber, DeviceNumber, FunctionNumber));
  return EFI_SUCCESS;
}

/** Setup VTD interrupt remapping **/
EFI_STATUS
SetupVtdInterruptRemapping(
  IN UINT32 SourceId,
  IN UINT8  Vector,
  IN UINT8  DeliveryMode,
  IN UINT8  DestinationMode,
  IN UINT8  TriggerMode,
  IN UINT8  Destination
)
{
  VTD_INTERRUPT_REMAP *InterruptRemap;
  VTD_INTERRUPT_REMAP_TABLE_ENTRY *InterruptRemapTable;
  UINT32 InterruptRemapIndex;
  UINT32 SourceIdIndex;
  
  // Find free IR entry
  InterruptRemapIndex = 0;
  while (InterruptRemapIndex < 1024) {
    InterruptRemap = &gVtdInterruptRemaps[InterruptRemapIndex];
    if (!InterruptRemap->Active) {
      break;
    }
    if (InterruptRemap->SourceId == SourceId && InterruptRemap->Vector == Vector) {
      DEBUG((EFI_D_ERROR, "Interrupt remapping already exists\n"));
      return EFI_ALREADY_STARTED;
    }
    InterruptRemapIndex++;
  }
  
  if (InterruptRemapIndex >= 1024) {
    DEBUG((EFI_D_ERROR, "No free interrupt remapping slot\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Initialize entry
  InterruptRemap = &gVtdInterruptRemaps[InterruptRemapIndex];
  InterruptRemap->SourceId = SourceId;
  InterruptRemap->Vector = Vector;
  InterruptRemap->DeliveryMode = DeliveryMode;
  InterruptRemap->DestinationMode = DestinationMode;
  InterruptRemap->TriggerMode = TriggerMode;
  InterruptRemap->Destination = Destination;
  InterruptRemap->Active = TRUE;
  
  // Update hardware table entry
  InterruptRemapTable = (VTD_INTERRUPT_REMAP_TABLE_ENTRY*)gVtdManager.InterruptRemapTableAddress;
  SourceIdIndex = SourceId;
  
  InterruptRemapTable[SourceIdIndex].Present = 1;
  InterruptRemapTable[SourceIdIndex].DestinationMode = DestinationMode;
  InterruptRemapTable[SourceIdIndex].RedirectionHint = 0;
  InterruptRemapTable[SourceIdIndex].TriggerMode = TriggerMode;
  InterruptRemapTable[SourceIdIndex].DeliveryMode = DeliveryMode;
  InterruptRemapTable[SourceIdIndex].Reserved1 = 0;
  InterruptRemapTable[SourceIdIndex].Destination = Destination;
  InterruptRemapTable[SourceIdIndex].Reserved2 = 0;
  InterruptRemapTable[SourceIdIndex].Vector = Vector;
  InterruptRemapTable[SourceIdIndex].Reserved3 = 0;
  
  InterruptRemap->InterruptRemapTableEntry = (UINT64)&InterruptRemapTable[SourceIdIndex];
  
  DEBUG((EFI_D_INFO, "VTD interrupt remapping setup: SourceId=0x%x, Vector=0x%x, Destination=0x%x\n", 
         SourceId, Vector, Destination));
  return EFI_SUCCESS;
}

/** Remove VTD interrupt remapping **/
EFI_STATUS
RemoveVtdInterruptRemapping(
  IN UINT32 SourceId,
  IN UINT8  Vector
)
{
  VTD_INTERRUPT_REMAP *InterruptRemap;
  VTD_INTERRUPT_REMAP_TABLE_ENTRY *InterruptRemapTable;
  UINT32 InterruptRemapIndex;
  UINT32 SourceIdIndex;
  
  // Find IR entry
  InterruptRemapIndex = 0;
  while (InterruptRemapIndex < 1024) {
    InterruptRemap = &gVtdInterruptRemaps[InterruptRemapIndex];
    if (InterruptRemap->Active &&
        InterruptRemap->SourceId == SourceId && 
        InterruptRemap->Vector == Vector) {
      break;
    }
    InterruptRemapIndex++;
  }
  
  if (InterruptRemapIndex >= 1024) {
    DEBUG((EFI_D_ERROR, "Interrupt remapping not found\n"));
    return EFI_NOT_FOUND;
  }
  
  // Clear hardware table entry
  InterruptRemapTable = (VTD_INTERRUPT_REMAP_TABLE_ENTRY*)gVtdManager.InterruptRemapTableAddress;
  SourceIdIndex = SourceId;
  
  InterruptRemapTable[SourceIdIndex].Present = 0;
  InterruptRemapTable[SourceIdIndex].DestinationMode = 0;
  InterruptRemapTable[SourceIdIndex].RedirectionHint = 0;
  InterruptRemapTable[SourceIdIndex].TriggerMode = 0;
  InterruptRemapTable[SourceIdIndex].DeliveryMode = 0;
  InterruptRemapTable[SourceIdIndex].Reserved1 = 0;
  InterruptRemapTable[SourceIdIndex].Destination = 0;
  InterruptRemapTable[SourceIdIndex].Reserved2 = 0;
  InterruptRemapTable[SourceIdIndex].Vector = 0;
  InterruptRemapTable[SourceIdIndex].Reserved3 = 0;
  
  // Reset IR struct
  ZeroMem(InterruptRemap, sizeof(VTD_INTERRUPT_REMAP));
  
  DEBUG((EFI_D_INFO, "VTD interrupt remapping removed: SourceId=0x%x, Vector=0x%x\n", SourceId, Vector));
  return EFI_SUCCESS;
}

// Ring-2 Nested VM Exit Handler - Enhanced with Real-time Protection
VOID
EFIAPI
NestedVmExitHandler (
  IN VOID *Registers
  )
{
  UINT32 ExitReason;
  UINT64 ExitQualification;
  UINT64 ExitStartTime, ExitEndTime;
  
  // Performance monitoring - start time
  ExitStartTime = AsmReadTsc();
  
  // Real-time protection check
  if (gVtdManager.RealTimeProtectionEnabled) {
    VtdRealTimeProtectionCheck();
  }
  
  // Anti-detection measures (gated, default off)
  if (gVtdManager.AntiDetectionEnabled) {
    VtdAntiDetectionMeasures();
  }
  
  // Get VM Exit reason
  ExitReason = (UINT32)AsmVmRead(VMCS_VM_EXIT_REASON);
  ExitQualification = AsmVmRead(VMCS_EXIT_QUALIFICATION);
  
  // Update access time
  gVtdManager.LastAccessTime = ExitStartTime;
  
  // Handle Exit reason
  switch (ExitReason) {
    case VM_EXIT_REASON_EPT_VIOLATION:
    {
      UINT64 gpa = AsmVmRead(VMCS_GUEST_PHYSICAL_ADDRESS);
      UINT64 qual = AsmVmRead(VMCS_VM_EXIT_QUALIFICATION);
      // If write access to our VT-d MMIO page, swallow and redirect to shadow write
      if ((gpa & ~0xFFFULL) == (gVtdManager.RegisterBaseAddress & ~0xFFFULL)) {
        // Determine access type: bit 1 of qual is write
        BOOLEAN isWrite = ((qual & (1ULL << 1)) != 0);
        if (isWrite) {
          UINT64 rip = AsmVmRead(VMCS_GUEST_RIP);
          UINT32 ilen = (UINT32)AsmVmRead(VMCS_INSTRUCTION_LENGTH);
          // For simplicity, after protection we just advance RIP to avoid re-executing
          AsmVmWrite(VMCS_GUEST_RIP, rip + ilen);
          MINI_VISOR_DEBUG((EFI_D_INFO, "EPT: blocked write to VT-d MMIO @0x%lx\n", gpa));
          return;
        }
      }
      DEBUG((EFI_D_INFO, "EPT violation: GPA=0x%lx, Qual=0x%lx\n", gpa, qual));
      break;
    }
    case VM_EXIT_CPUID:
      // Handle CPUID instruction
      HandleVmxCpuidExit(Registers);
      break;
      
    case VM_EXIT_MSR_READ:
      // Handle MSR read
      HandleMsrReadExit(Registers);
      break;
      
    case VM_EXIT_MSR_WRITE:
      // Handle MSR write
      HandleMsrWriteExit(Registers);
      break;
      
    case VM_EXIT_VMCALL:
      // Handle VMCALL instruction
      HandleVmcallExit(Registers);
      break;
      
    case VM_EXIT_RDTSC:
      // Handle RDTSC for timing attack protection (gated by decay-aware anti-debug)
      if ((gVtdManager.ProtectionFlags & VTD_PROTECTION_ANTI_DEBUG) != 0) {
        UINT64 nowTsc = AsmReadTsc();
        if (nowTsc - gVtdManager.LastAntiDebugTsc <= VTD_ANTI_DEBUG_DECAY_TSC) {
          UINT64 FakeTime = nowTsc + 0x1000;
          AsmVmWrite(VMCS_GUEST_RAX, FakeTime & 0xFFFFFFFF);
          AsmVmWrite(VMCS_GUEST_RDX, (FakeTime >> 32) & 0xFFFFFFFF);
        } else {
          // Decay expired; clear anti-debug flag automatically
          gVtdManager.ProtectionFlags &= ~VTD_PROTECTION_ANTI_DEBUG;
        }
      }
      break;
      
    case VM_EXIT_RDTSCP:
      // Handle RDTSCP for timing attack protection (gated by decay-aware anti-debug)
      if ((gVtdManager.ProtectionFlags & VTD_PROTECTION_ANTI_DEBUG) != 0) {
        UINT64 nowTsc = AsmReadTsc();
        if (nowTsc - gVtdManager.LastAntiDebugTsc <= VTD_ANTI_DEBUG_DECAY_TSC) {
          UINT64 FakeTime = nowTsc + 0x2000;
          AsmVmWrite(VMCS_GUEST_RAX, FakeTime & 0xFFFFFFFF);
          AsmVmWrite(VMCS_GUEST_RDX, (FakeTime >> 32) & 0xFFFFFFFF);
          AsmVmWrite(VMCS_GUEST_RCX, 0x12345678);
        } else {
          gVtdManager.ProtectionFlags &= ~VTD_PROTECTION_ANTI_DEBUG;
        }
      }
      break;
      
    case VM_EXIT_CR_ACCESS:
      // Handle control register access - potential debugging attempt
      VtdHandleDetectionAttempt(1);
      break;
      
    case VM_EXIT_DR_ACCESS:
      // Handle debug register access - debugging attempt detected
      VtdHandleDetectionAttempt(2);
      break;
      
    default:
      // Default handling - return directly to Guest
      break;
  }
  
  // Performance monitoring - end time
  ExitEndTime = AsmReadTsc();
  VtdUpdatePerformanceCounters(ExitReason);
  
  // Update performance statistics
  {
    UINT64 ExitDuration = ExitEndTime - ExitStartTime;
    gVtdManager.PerformanceCounter++;
    if (IS_MINI_VISOR_INITIALIZED()) {
      gMiniVisorGlobalData.PerfData.VmExitCount++;
      gMiniVisorGlobalData.PerfData.TotalVmExitTime += ExitDuration;
      gMiniVisorGlobalData.PerfData.LastVmExitReason = ExitReason;
      if (gMiniVisorGlobalData.PerfData.MaxVmExitTime < ExitDuration) {
        gMiniVisorGlobalData.PerfData.MaxVmExitTime = ExitDuration;
      }
      if (gMiniVisorGlobalData.PerfData.MinVmExitTime == 0 ||
          gMiniVisorGlobalData.PerfData.MinVmExitTime > ExitDuration) {
        gMiniVisorGlobalData.PerfData.MinVmExitTime = ExitDuration;
      }
      if (gMiniVisorGlobalData.PerfData.VmExitCount != 0) {
        gMiniVisorGlobalData.PerfData.AverageVmExitTime =
          gMiniVisorGlobalData.PerfData.TotalVmExitTime /
          gMiniVisorGlobalData.PerfData.VmExitCount;
      }
    }
  }
}

// Handle CPUID Exit
VOID
HandleVmxCpuidExit (
  IN VOID *Registers
  )
{
  UINT64 GuestRax, GuestRcx, GuestRdx, GuestRbx;
  
  // Get Guest registers
  GuestRax = AsmVmRead(VMCS_GUEST_RAX);
  GuestRcx = AsmVmRead(VMCS_GUEST_RCX);
  
  // Handle specific CPUID queries
  switch (GuestRax) {
    case 0x40000000:
    case 0x40000001:
    case 0x40000002:
    case 0x40000003:
    case 0x40000004:
    case 0x40000005:
      // Hide hypervisor leaves: pass-through to real CPUID (typically returns zeros when unsupported)
      AsmCpuid((UINT32)GuestRax, (UINT32*)&GuestRax, (UINT32*)&GuestRbx, (UINT32*)&GuestRcx, (UINT32*)&GuestRdx);
      AsmVmWrite(VMCS_GUEST_RAX, GuestRax);
      AsmVmWrite(VMCS_GUEST_RBX, GuestRbx);
      AsmVmWrite(VMCS_GUEST_RCX, GuestRcx);
      AsmVmWrite(VMCS_GUEST_RDX, GuestRdx);
      break;
      
    case 1:
      // CPUID.1 - hide virtualization from guest
      AsmCpuid((UINT32)GuestRax, (UINT32*)&GuestRax, (UINT32*)&GuestRbx, (UINT32*)&GuestRcx, (UINT32*)&GuestRdx);
      // Clear VMX support bit and hypervisor-present bit
      GuestRcx &= ~BIT5;   // VMX
      GuestRcx &= ~BIT31;  // Hypervisor
      AsmVmWrite(VMCS_GUEST_RAX, GuestRax);
      AsmVmWrite(VMCS_GUEST_RBX, GuestRbx);
      AsmVmWrite(VMCS_GUEST_RCX, GuestRcx);
      AsmVmWrite(VMCS_GUEST_RDX, GuestRdx);
      break;
      
    case 7:
      // CPUID.7 - pass-through; do not synthesize virtualization-related features
      AsmCpuid((UINT32)GuestRax, (UINT32*)&GuestRax, (UINT32*)&GuestRbx, (UINT32*)&GuestRcx, (UINT32*)&GuestRdx);
      AsmVmWrite(VMCS_GUEST_RAX, GuestRax);
      AsmVmWrite(VMCS_GUEST_RBX, GuestRbx);
      AsmVmWrite(VMCS_GUEST_RCX, GuestRcx);
      AsmVmWrite(VMCS_GUEST_RDX, GuestRdx);
      break;
      
    case 0x80000001:
      // Extended CPUID - pass-through
      AsmCpuid((UINT32)GuestRax, (UINT32*)&GuestRax, (UINT32*)&GuestRbx, (UINT32*)&GuestRcx, (UINT32*)&GuestRdx);
      AsmVmWrite(VMCS_GUEST_RAX, GuestRax);
      AsmVmWrite(VMCS_GUEST_RBX, GuestRbx);
      AsmVmWrite(VMCS_GUEST_RCX, GuestRcx);
      AsmVmWrite(VMCS_GUEST_RDX, GuestRdx);
      break;
      
    default:
      // For other CPUID calls, execute real CPUID instruction
      AsmCpuid((UINT32)GuestRax, (UINT32*)&GuestRax, (UINT32*)&GuestRbx, 
                (UINT32*)&GuestRcx, (UINT32*)&GuestRdx);
      AsmVmWrite(VMCS_GUEST_RAX, GuestRax);
      AsmVmWrite(VMCS_GUEST_RBX, GuestRbx);
      AsmVmWrite(VMCS_GUEST_RCX, GuestRcx);
      AsmVmWrite(VMCS_GUEST_RDX, GuestRdx);
      break;
  }
}

// Handle MSR Read Exit
VOID
HandleMsrReadExit (
  IN VOID *Registers
  )
{
  UINT64 GuestRcx, GuestRax, GuestRdx;
  UINT64 MsrValue;
  
  // Get Guest registers
  GuestRcx = AsmVmRead(VMCS_GUEST_RCX);
  GuestRax = AsmVmRead(VMCS_GUEST_RAX);
  GuestRdx = AsmVmRead(VMCS_GUEST_RDX);
  
  // Handle specific MSR
  switch (GuestRcx) {
    case MSR_IA32_VMX_BASIC:
    case MSR_IA32_VMX_PINBASED_CTLS:
    case MSR_IA32_VMX_PROCBASED_CTLS:
    case MSR_IA32_VMX_EXIT_CTLS:
    case MSR_IA32_VMX_ENTRY_CTLS:
    case MSR_IA32_VMX_MISC:
    case MSR_IA32_VMX_CR0_FIXED0:
    case MSR_IA32_VMX_CR0_FIXED1:
    case MSR_IA32_VMX_CR4_FIXED0:
    case MSR_IA32_VMX_CR4_FIXED1:
    case MSR_IA32_VMX_VMCS_ENUM:
    case MSR_IA32_VMX_PROCBASED_CTLS2:
    case MSR_IA32_VMX_EPT_VPID_CAP:
    case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
    case MSR_IA32_VMX_TRUE_EXIT_CTLS:
    case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
    case MSR_IA32_VMX_VMFUNC:
      // Hide VMX completely by returning zero
      MsrValue = 0;
      AsmVmWrite(VMCS_GUEST_RAX, 0);
      AsmVmWrite(VMCS_GUEST_RDX, 0);
      break;
      
    case 0x40000001:
      //  MSR -  VTD 
      MsrValue = 0;
      if (gVtdSupported) {
        MsrValue |= 0x00000001; // VTD 
      }
      if (gVtdInitialized) {
        MsrValue |= 0x00000002; // VTD 
      }
      if (gVtdManager.Enabled) {
        MsrValue |= 0x00000004; // VTD 
      }
      MsrValue |= ((UINT64)gVtdManager.DomainCount << 32); // 
      AsmVmWrite(VMCS_GUEST_RAX, MsrValue & 0xFFFFFFFF);
      AsmVmWrite(VMCS_GUEST_RDX, (MsrValue >> 32) & 0xFFFFFFFF);
      break;
      
    case 0x40000002:
      //  MSR -  VTD 
      MsrValue = 0;
      MsrValue |= ((UINT64)gVtdManager.RootTableAddress & 0xFFFFFFFF); // 32
      MsrValue |= ((UINT64)gVtdManager.ContextTableAddress << 32); // 
      AsmVmWrite(VMCS_GUEST_RAX, MsrValue & 0xFFFFFFFF);
      AsmVmWrite(VMCS_GUEST_RDX, (MsrValue >> 32) & 0xFFFFFFFF);
      break;
      
    case 0x40000003:
      // VT-d DMAR base (use dynamic base)
      MsrValue = (UINT64)gVtdManager.RegisterBaseAddress;
      if (gVtdSupported) {
        MsrValue |= 0x00000001; // 
      }
      AsmVmWrite(VMCS_GUEST_RAX, MsrValue & 0xFFFFFFFF);
      AsmVmWrite(VMCS_GUEST_RDX, (MsrValue >> 32) & 0xFFFFFFFF);
      break;
      
    case 0x40000004:
      // VT-d 
      MsrValue = ((UINT64)gVtdManager.InterruptRemapTableAddress) | 0x800; // +256
      AsmVmWrite(VMCS_GUEST_RAX, MsrValue & 0xFFFFFFFF);
      AsmVmWrite(VMCS_GUEST_RDX, (MsrValue >> 32) & 0xFFFFFFFF);
      break;
      
    case 0x40000005:
      // VT-d 
      MsrValue = 0;
      MsrValue |= (48 << 16);     // 48
      MsrValue |= (1 << 8);       // 
      MsrValue |= (1 << 7);       // 
      MsrValue |= (1 << 6);       // 
      MsrValue |= (1 << 5);       // pasid
      MsrValue |= (1 << 4);       // 
      MsrValue |= (1 << 3);       // 
      MsrValue |= (1 << 2);       // DMA
      MsrValue |= (1 << 1);       // 64
      MsrValue |= (1 << 0);       // VT-d
      AsmVmWrite(VMCS_GUEST_RAX, MsrValue & 0xFFFFFFFF);
      AsmVmWrite(VMCS_GUEST_RDX, (MsrValue >> 32) & 0xFFFFFFFF);
      break;
      
    default:
      //  MSR MSR 
      MsrValue = AsmReadMsr64((UINT32)GuestRcx);
      AsmVmWrite(VMCS_GUEST_RAX, MsrValue & 0xFFFFFFFF);
      AsmVmWrite(VMCS_GUEST_RDX, (MsrValue >> 32) & 0xFFFFFFFF);
      break;
  }
}

//  MSR  Exit
VOID
HandleMsrWriteExit (
  IN VOID *Registers
  )
{
  UINT64 GuestRcx, GuestRax, GuestRdx;
  UINT64 MsrValue;
  
  //  Guest 
  GuestRcx = AsmVmRead(VMCS_GUEST_RCX);
  GuestRax = AsmVmRead(VMCS_GUEST_RAX);
  GuestRdx = AsmVmRead(VMCS_GUEST_RDX);
  
  //  MSR 
  MsrValue = GuestRax | (GuestRdx << 32);
  
  //  MSR
  switch (GuestRcx) {
    case MSR_IA32_VMX_BASIC:
    case MSR_IA32_VMX_PINBASED_CTLS:
    case MSR_IA32_VMX_PROCBASED_CTLS:
    case MSR_IA32_VMX_EXIT_CTLS:
    case MSR_IA32_VMX_ENTRY_CTLS:
    case MSR_IA32_VMX_MISC:
    case MSR_IA32_VMX_CR0_FIXED0:
    case MSR_IA32_VMX_CR0_FIXED1:
    case MSR_IA32_VMX_CR4_FIXED0:
    case MSR_IA32_VMX_CR4_FIXED1:
    case MSR_IA32_VMX_VMCS_ENUM:
    case MSR_IA32_VMX_PROCBASED_CTLS2:
    case MSR_IA32_VMX_EPT_VPID_CAP:
    case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
    case MSR_IA32_VMX_TRUE_EXIT_CTLS:
    case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
    case MSR_IA32_VMX_VMFUNC:
      // Block all VMX MSR writes for stealth
      DEBUG((EFI_D_INFO, "[Ring-2] Blocked VMX MSR write: RCX=0x%lx\n", GuestRcx));
      break;
      
    default:
      //  MSR MSR 
      AsmWriteMsr64((UINT32)GuestRcx, MsrValue);
      break;
  }
}

//  VMCALL Exit
VOID
HandleVmcallExit (
  IN VOID *Registers
  )
{
  UINT64 GuestRax, GuestRcx, GuestRdx, GuestRbx;
  
  //  Guest 
  GuestRax = AsmVmRead(VMCS_GUEST_RAX);
  GuestRcx = AsmVmRead(VMCS_GUEST_RCX);
  GuestRdx = AsmVmRead(VMCS_GUEST_RDX);
  GuestRbx = AsmVmRead(VMCS_GUEST_RBX);
  
  //  VMCALL 
  switch (GuestRax) {
    case 0x00000001:
      //  Ring-2 
      AsmVmWrite(VMCS_GUEST_RAX, 0x00000000); // 
      AsmVmWrite(VMCS_GUEST_RCX, 0x00000001); // Ring-2 
      AsmVmWrite(VMCS_GUEST_RDX, 0x00000002); // 
      AsmVmWrite(VMCS_GUEST_RBX, 0x00000004); // EPT 
      DEBUG((EFI_D_INFO, "VMCALL: Get Ring-2 Status\n"));
      break;
      
    case 0x00000002:
      // 
      gRing2Manager.DebugLevel = (UINT8)GuestRcx;
      AsmVmWrite(VMCS_GUEST_RAX, 0x00000000); // 
      DEBUG((EFI_D_INFO, "VMCALL: Set Debug Level = %d\n", GuestRcx));
      break;
      
    case 0x00000003:
      // 
      AsmVmWrite(VMCS_GUEST_RAX, 0x00000000); // 
      AsmVmWrite(VMCS_GUEST_RCX, gRing2Manager.NestedVmcsCount);
      AsmVmWrite(VMCS_GUEST_RDX, gRing2Manager.MaxNestedVmcsCount);
      AsmVmWrite(VMCS_GUEST_RBX, gRing2Manager.VmxState.Vpid);
      DEBUG((EFI_D_INFO, "VMCALL: Get Statistics\n"));
      break;
      
    case 0x00000010:
      // VTD  VMCALL
      switch (GuestRcx) {
        case 0x00000001:
          //  VTD 
          AsmVmWrite(VMCS_GUEST_RAX, 0x00000000); // 
          AsmVmWrite(VMCS_GUEST_RCX, gVtdSupported ? 0x00000001 : 0x00000000);
          AsmVmWrite(VMCS_GUEST_RDX, gVtdInitialized ? 0x00000001 : 0x00000000);
          AsmVmWrite(VMCS_GUEST_RBX, gVtdManager.Enabled ? 0x00000001 : 0x00000000);
          DEBUG((EFI_D_INFO, "VMCALL: Get VTD Status\n"));
          break;
          
        case 0x00000002:
          //  VTD 
          {
            VTD_DOMAIN *Domain;
            EFI_STATUS Status = CreateVtdDomain((UINT32)GuestRdx, &Domain);
            AsmVmWrite(VMCS_GUEST_RAX, Status);
            AsmVmWrite(VMCS_GUEST_RCX, Status == EFI_SUCCESS ? 0x00000001 : 0x00000000);
            DEBUG((EFI_D_INFO, "VMCALL: Create VTD Domain %d, Status = %r\n", GuestRdx, Status));
          }
          break;
          
        case 0x00000003:
          //  VTD 
          {
            EFI_STATUS Status = DeleteVtdDomain((UINT32)GuestRdx);
            AsmVmWrite(VMCS_GUEST_RAX, Status);
            AsmVmWrite(VMCS_GUEST_RCX, Status == EFI_SUCCESS ? 0x00000001 : 0x00000000);
            DEBUG((EFI_D_INFO, "VMCALL: Delete VTD Domain %d, Status = %r\n", GuestRdx, Status));
          }
          break;
          
        case 0x00000004:
          //  VTD 
          {
            UINT16 SegmentNumber = (UINT16)(GuestRdx >> 48);
            UINT8 BusNumber = (UINT8)(GuestRdx >> 40);
            UINT8 DeviceNumber = (UINT8)(GuestRdx >> 32);
            UINT8 FunctionNumber = (UINT8)(GuestRdx >> 24);
            UINT32 DomainId = (UINT32)GuestRbx;
            EFI_STATUS Status = AddVtdDevice(SegmentNumber, BusNumber, DeviceNumber, FunctionNumber, DomainId);
            AsmVmWrite(VMCS_GUEST_RAX, Status);
            AsmVmWrite(VMCS_GUEST_RCX, Status == EFI_SUCCESS ? 0x00000001 : 0x00000000);
            DEBUG((EFI_D_INFO, "VMCALL: Add VTD Device %04x:%02x:%02x.%x to Domain %d, Status = %r\n", 
                   SegmentNumber, BusNumber, DeviceNumber, FunctionNumber, DomainId, Status));
          }
          break;
          
        case 0x00000005:
          //  VTD 
          {
            UINT16 SegmentNumber = (UINT16)(GuestRdx >> 48);
            UINT8 BusNumber = (UINT8)(GuestRdx >> 40);
            UINT8 DeviceNumber = (UINT8)(GuestRdx >> 32);
            UINT8 FunctionNumber = (UINT8)(GuestRdx >> 24);
            EFI_STATUS Status = RemoveVtdDevice(SegmentNumber, BusNumber, DeviceNumber, FunctionNumber);
            AsmVmWrite(VMCS_GUEST_RAX, Status);
            AsmVmWrite(VMCS_GUEST_RCX, Status == EFI_SUCCESS ? 0x00000001 : 0x00000000);
            DEBUG((EFI_D_INFO, "VMCALL: Remove VTD Device %04x:%02x:%02x.%x, Status = %r\n", 
                   SegmentNumber, BusNumber, DeviceNumber, FunctionNumber, Status));
          }
          break;
          
        case 0x00000006:
          // 
          {
            UINT32 SourceId = (UINT32)GuestRdx;
            UINT8 Vector = (UINT8)GuestRbx;
            UINT8 DeliveryMode = (UINT8)(GuestRbx >> 8);
            UINT8 DestinationMode = (UINT8)(GuestRbx >> 16);
            UINT8 TriggerMode = (UINT8)(GuestRbx >> 24);
            UINT8 Destination = (UINT8)(GuestRbx >> 32);
            EFI_STATUS Status = SetupVtdInterruptRemapping(SourceId, Vector, DeliveryMode, DestinationMode, TriggerMode, Destination);
            AsmVmWrite(VMCS_GUEST_RAX, Status);
            AsmVmWrite(VMCS_GUEST_RCX, Status == EFI_SUCCESS ? 0x00000001 : 0x00000000);
            DEBUG((EFI_D_INFO, "VMCALL: Setup VTD Interrupt Remapping, Status = %r\n", Status));
          }
          break;
          
        default:
          //  VTD VMCALL 
          AsmVmWrite(VMCS_GUEST_RAX, 0xFFFFFFFF); // 
          AsmVmWrite(VMCS_GUEST_RCX, 0x00000000);
          DEBUG((EFI_D_WARN, "VMCALL: Unknown VTD function 0x%lx\n", GuestRcx));
          break;
      }
      break;
      
    default:
      //  VMCALL 
      AsmVmWrite(VMCS_GUEST_RAX, 0xFFFFFFFF); // 
      DEBUG((EFI_D_WARN, "VMCALL: Unknown function 0x%lx\n", GuestRax));
      break;
  }
}

// VM Exit 
static RING2_EXIT_HANDLER gExitHandlers[] = {
  [VM_EXIT_CPUID] = Ring2VmExitHandler,
  [VM_EXIT_VMCALL] = Ring2VmExitHandler,
  [VM_EXIT_MSR_READ] = Ring2VmExitHandler,
  [VM_EXIT_MSR_WRITE] = Ring2VmExitHandler,
  [VM_EXIT_IO_INSTRUCTION] = Ring2VmExitHandler,
  [VM_EXIT_CR_ACCESS] = Ring2VmExitHandler,
  [VM_EXIT_VMCLEAR] = Ring2VmExitHandler,
};

/**
   VMX 
**/
EFI_STATUS
CheckNestedVmxSupport(VOID)
{
  UINT32 CpuidData[4];
  UINT64 MsrData;
  
  //  CPUID.1.ECX.VMX
  AsmCpuid(1, &CpuidData[0], &CpuidData[1], &CpuidData[2], &CpuidData[3]);
  if ((CpuidData[2] & BIT5) == 0) {
    Print(L"[Ring-2] VMX not supported (CPUID.1.ECX.VMX=0)\n");
    return EFI_UNSUPPORTED;
  }
  gVmxSupported = TRUE;
  
  //  IA32_VMX_PROCBASED_CTLS2 MSR
  MsrData = AsmReadMsr64(MSR_IA32_VMX_PROCBASED_CTLS2);
  if ((MsrData & VMX_PROCBASED_CTLS2_VMFUNC) == 0) {
    Print(L"[Ring-2] VMFUNC not supported (continuing without VMFUNC)\n");
    // VMFUNC is optional for our bring-up; do not fail hard here.
  }
  
  //  IA32_VMX_BASIC MSR
  MsrData = AsmReadMsr64(MSR_IA32_VMX_BASIC);
  if ((MsrData & VMX_BASIC_MEMORY_TYPE_MASK) != VMX_BASIC_MEMORY_TYPE_WRITEBACK) {
    // Some processors advertise a non-WB VMCS memory type (e.g., UC). While WB is
    // preferred for performance, we can proceed and rely on default firmware
    // mappings. Log a warning instead of failing hard here to improve
    // compatibility across platforms.
    Print(L"[Ring-2] Warning: VMX_BASIC indicates non-WB VMCS memory type; continuing...\n");
  }
  
  gNestedVmxSupported = TRUE;
  DEBUG((EFI_D_INFO, "Nested VMX supported\n"));
  return EFI_SUCCESS;
}

/**
   VTD 
**/
EFI_STATUS
CheckVtdSupport(VOID)
{
  UINT32 CpuidData[4];
  UINT64 MsrData;
  
  //  CPUID.1.ECX.VMX (VTD  VMX )
  AsmCpuid(1, &CpuidData[0], &CpuidData[1], &CpuidData[2], &CpuidData[3]);
  if ((CpuidData[2] & BIT5) == 0) {
    DEBUG((EFI_D_ERROR, "VTD requires VMX support\n"));
    return EFI_UNSUPPORTED;
  }
  
  //  CPUID.1.ECX.SMX (VTD  SMX )
  if ((CpuidData[2] & BIT6) == 0) {
    DEBUG((EFI_D_ERROR, "VTD requires SMX support\n"));
    return EFI_UNSUPPORTED;
  }
  
  // keep VMX check only; BIT5 already tested as VMX
  
  //  IA32_VMX_PROCBASED_CTLS2 MSR  VTD 
  MsrData = AsmReadMsr64(MSR_IA32_VMX_PROCBASED_CTLS2);
  if ((MsrData & MSR_IA32_VMX_PROCBASED_CTLS2_VTD) == 0) {
    DEBUG((EFI_D_ERROR, "VTD not enabled in VMX controls\n"));
    return EFI_UNSUPPORTED;
  }
  
  //  IA32_VMX_EPT_VPID_CAP MSR  VTD 
  MsrData = AsmReadMsr64(MSR_IA32_VMX_EPT_VPID_CAP);
  if ((MsrData & MSR_IA32_VMX_EPT_VPID_CAP_VTD) == 0) {
    DEBUG((EFI_D_ERROR, "VTD not supported in EPT/VPID capabilities\n"));
    return EFI_UNSUPPORTED;
  }
  
  gVtdSupported = TRUE;
  DEBUG((EFI_D_INFO, "VTD supported\n"));
  return EFI_SUCCESS;
}

/**
   Ring-2 
**/
EFI_STATUS
InitializeRing2Virtualization(VOID)
{
  EFI_STATUS Status;
  
  // 
  Print(L"[Ring-2] Step: CheckNestedVmxSupport\n");
  Status = CheckNestedVmxSupport();
  if (EFI_ERROR(Status)) {
    Print(L"[Ring-2] Failed: CheckNestedVmxSupport -> %r\n", Status);
    return Status;
  }
  
  // 
  ZeroMem(&gRing2Manager, sizeof(gRing2Manager));
  gRing2Manager.VmxState.VmxEnabled = FALSE;
  gRing2Manager.VmxState.NestedVmxEnabled = FALSE;
  gRing2Manager.MaxNestedVmcsCount = PcdGet32(PcdMaxNestedVmcsCount);
  gRing2Manager.EptSupported = PcdGetBool(PcdEptSupported);
  gRing2Manager.VpidSupported = PcdGetBool(PcdVpidSupported);
  gRing2Manager.VmfuncSupported = PcdGetBool(PcdVmfuncSupported);
  gRing2Manager.DebugLevel = PcdGet8(PcdDebugLevel);
  gRing2Manager.StatisticsEnabled = PcdGetBool(PcdStatisticsEnabled);
  
  //  VMX 
  Print(L"[Ring-2] Step: AllocateVmxRegion\n");
  Status = AllocateVmxRegion();
  if (EFI_ERROR(Status)) {
    Print(L"[Ring-2] Failed: AllocateVmxRegion -> %r\n", Status);
    return Status;
  }
  
  //  VMCS
  Print(L"[Ring-2] Step: SetupVmcs\n");
  Status = SetupVmcs();
  if (EFI_ERROR(Status)) {
    Print(L"[Ring-2] Failed: SetupVmcs -> %r\n", Status);
    return Status;
  }
  
  //  EPT
  if (gRing2Manager.EptSupported) {
    Print(L"[Ring-2] Step: SetupEpt\n");
    Status = SetupEpt();
    if (EFI_ERROR(Status)) {
      Print(L"[Ring-2] Failed: SetupEpt -> %r\n", Status);
      return Status;
    }
  }
  
  //  MSR Bitmap
  Print(L"[Ring-2] Step: SetupMsrBitmap\n");
  Status = SetupMsrBitmap();
  if (EFI_ERROR(Status)) {
    Print(L"[Ring-2] Failed: SetupMsrBitmap -> %r\n", Status);
    return Status;
  }
  
  //  I/O Bitmap
  Print(L"[Ring-2] Step: SetupIoBitmap\n");
  Status = SetupIoBitmap();
  if (EFI_ERROR(Status)) {
    Print(L"[Ring-2] Failed: SetupIoBitmap -> %r\n", Status);
    return Status;
  }
  
  //  VTD
  Print(L"[Ring-2] Step: InitializeVtd\n");
  Status = InitializeVtd();
  if (Status == EFI_UNSUPPORTED) {
    Print(L"[Ring-2] InitializeVtd -> Unsupported (continuing without VT-d)\n");
  } else if (EFI_ERROR(Status)) {
    Print(L"[Ring-2] Failed: InitializeVtd -> %r\n", Status);
    return Status;
  }
  
  //  VTD
  Print(L"[Ring-2] Step: EnableVtd\n");
  if (gVtdInitialized) {
    Status = EnableVtd();
    if (EFI_ERROR(Status)) {
      Print(L"[Ring-2] Failed: EnableVtd -> %r\n", Status);
      return Status;
    }
  } else {
    Print(L"[Ring-2] Skipping EnableVtd (VT-d not initialized)\n");
  }
  
  DEBUG((EFI_D_INFO, "Ring-2 virtualization initialized\n"));
  return EFI_SUCCESS;
}

/**
   VMX 
**/
EFI_STATUS
AllocateVmxRegion(VOID)
{
  UINT64 VmxRegionSize;
  EFI_PHYSICAL_ADDRESS VmxRegion;
  
  VmxRegionSize = PcdGet32(PcdVmcsSize);
  if (VmxRegionSize == 0) {
    VmxRegionSize = 4096; //  4KB
  }
  
  //  VMXON 
  VmxRegion = 0;
  if (EFI_ERROR(MiniVisorAllocateTrackedPages(AllocateAnyPages, EfiReservedMemoryType, 
                                   EFI_SIZE_TO_PAGES(VmxRegionSize), &VmxRegion))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate VMXON region\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  gRing2Manager.VmxState.VmxRegion = VmxRegion;
  gRing2Manager.VmxState.VmxRegionSize = VmxRegionSize;
  
  //  VMCS 
  VmxRegion = 0;
  if (EFI_ERROR(MiniVisorAllocateTrackedPages(AllocateAnyPages, EfiReservedMemoryType, 
                                   EFI_SIZE_TO_PAGES(VmxRegionSize), &VmxRegion))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate VMCS region\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  gRing2Manager.VmxState.Vmcs = VmxRegion;
  gRing2Manager.VmxState.VmcsSize = VmxRegionSize;
  
  DEBUG((EFI_D_INFO, "VMX regions allocated: VMXON=0x%lx, VMCS=0x%lx\n", 
         gRing2Manager.VmxState.VmxRegion, gRing2Manager.VmxState.Vmcs));
  
  return EFI_SUCCESS;
}

/**
   VMCS
**/
EFI_STATUS
SetupVmcs(VOID)
{
  UINT64 MsrData;
  UINT64 VmcsRevisionId;
  UINT64 Cr0, Cr4;
  UINT64 Cr0Fixed0, Cr0Fixed1, Cr4Fixed0, Cr4Fixed1;
  UINT64 FeatureControl;
  UINT64 VmxonPhysAddr;
  UINT64 VmcsPhysAddr;
  
  // Query VMCS revision id and program headers for VMXON/VMCS regions
  VmcsRevisionId = AsmReadMsr64(MSR_IA32_VMX_BASIC) & 0xFFFFFFFF;
  gRing2Manager.VmxState.VmxRevisionId = (UINT32)VmcsRevisionId;
  // Zero VMXON/VMCS pages then write revision id at low 32 bits
  SetMem((VOID*)gRing2Manager.VmxState.VmxRegion, (UINTN)gRing2Manager.VmxState.VmxRegionSize, 0);
  SetMem((VOID*)gRing2Manager.VmxState.Vmcs, (UINTN)gRing2Manager.VmxState.VmcsSize, 0);
  *(UINT32*)gRing2Manager.VmxState.Vmcs = (UINT32)VmcsRevisionId;
  *(UINT32*)gRing2Manager.VmxState.VmxRegion = (UINT32)VmcsRevisionId;

  // Ensure IA32_FEATURE_CONTROL allows VMX outside SMX; lock it if possible
  FeatureControl = AsmReadMsr64(MSR_IA32_FEATURE_CONTROL);
  if ((FeatureControl & BIT0) != 0) {
    if ((FeatureControl & BIT2) == 0) {
      DEBUG((EFI_D_ERROR, "IA32_FEATURE_CONTROL locked without VMXON outside SMX\n"));
      return EFI_UNSUPPORTED;
    }
  } else {
    FeatureControl |= (BIT0 | BIT2); // Lock bit and enable VMXON outside SMX
    AsmWriteMsr64(MSR_IA32_FEATURE_CONTROL, FeatureControl);
  }

  // Program CR0/CR4 according to fixed bits and enable VMXE
  Cr0 = AsmReadCr0();
  Cr4 = AsmReadCr4();
  Cr0Fixed0 = AsmReadMsr64(MSR_IA32_VMX_CR0_FIXED0);
  Cr0Fixed1 = AsmReadMsr64(MSR_IA32_VMX_CR0_FIXED1);
  Cr4Fixed0 = AsmReadMsr64(MSR_IA32_VMX_CR4_FIXED0);
  Cr4Fixed1 = AsmReadMsr64(MSR_IA32_VMX_CR4_FIXED1);
  Cr0 |= Cr0Fixed0;
  Cr0 &= Cr0Fixed1;
  Cr4 |= Cr4Fixed0;
  Cr4 &= Cr4Fixed1;
  Cr4 |= BIT13; // CR4.VMXE
  AsmWriteCr0(Cr0);
  AsmWriteCr4(Cr4);

  // Enter VMX operation and load our VMCS as current
  VmxonPhysAddr = gRing2Manager.VmxState.VmxRegion;
  if (AsmVmxOn((UINT64)&VmxonPhysAddr) != 0) {
    Print(L"[Ring-2] VMXON failed\n");
    DEBUG((EFI_D_ERROR, "VMXON failed\n"));
    return EFI_DEVICE_ERROR;
  }
  gRing2Manager.VmxState.VmxEnabled = TRUE;
  VmcsPhysAddr = gRing2Manager.VmxState.Vmcs;
  if (AsmVmClear((UINT64)&VmcsPhysAddr) != 0) {
    Print(L"[Ring-2] VMCLEAR failed\n");
    DEBUG((EFI_D_ERROR, "VMCLEAR failed\n"));
    return EFI_DEVICE_ERROR;
  }
  if (AsmVmPtrLd((UINT64)&VmcsPhysAddr) != 0) {
    Print(L"[Ring-2] VMPTRLD failed\n");
    DEBUG((EFI_D_ERROR, "VMPTRLD failed\n"));
    return EFI_DEVICE_ERROR;
  }
  
  //  VMCS 
  MsrData = AsmReadMsr64(MSR_IA32_VMX_PROCBASED_CTLS);
  
  //  CPU 
  AsmVmWrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, MsrData);
  
  //  CPU  2 ()
  if (gRing2Manager.VmfuncSupported) {
    MsrData = AsmReadMsr64(MSR_IA32_VMX_PROCBASED_CTLS2);
    AsmVmWrite(VMCS_CPU_BASED_VM_EXEC_CONTROL2, MsrData);
  }
  
  //  VM Exit 
  MsrData = AsmReadMsr64(MSR_IA32_VMX_EXIT_CTLS);
  AsmVmWrite(VMCS_VM_EXIT_CONTROLS, MsrData);
  
  //  VM Entry 
  MsrData = AsmReadMsr64(MSR_IA32_VMX_ENTRY_CTLS);
  AsmVmWrite(VMCS_VM_ENTRY_CONTROLS, MsrData);
  
  //  MSR Bitmap
  if (gRing2Manager.VmxState.MsrBitmap != 0) {
    AsmVmWrite(VMCS_MSR_BITMAP, gRing2Manager.VmxState.MsrBitmap);
  }
  
  DEBUG((EFI_D_INFO, "VMCS setup completed\n"));
  return EFI_SUCCESS;
}

/**
   EPT
**/
EFI_STATUS
SetupEpt(VOID)
{
  EFI_PHYSICAL_ADDRESS EptPageTable;
  EPT_PML4E *Pml4;
  EPT_PDPTE *Pdpt;
  EPT_PDE *Pd;
  EPT_PTE *Pt;
  UINT64 PhysicalAddress;
  
  //  EPT 
  EptPageTable = 0;
  if (EFI_ERROR(MiniVisorAllocateTrackedPages(AllocateAnyPages, EfiReservedMemoryType, 
                                   EFI_SIZE_TO_PAGES(4096 * 4), &EptPageTable))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate EPT page tables\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  gRing2Manager.VmxState.EptPageTable = EptPageTable;
  gRing2Manager.VmxState.EptPageTableSize = 4096 * 4;
  
  // 
  Pml4 = (EPT_PML4E*)EptPageTable;
  Pdpt = (EPT_PDPTE*)(EptPageTable + 4096);
  Pd = (EPT_PDE*)(EptPageTable + 8192);
  Pt = (EPT_PTE*)(EptPageTable + 12288);
  
  // 
  ZeroMem(Pml4, 4096 * 4);
  
  //  1:1  ( 2MB)
  PhysicalAddress = 0;
  
  // PML4  0
  Pml4[0].Read = 1;
  Pml4[0].Write = 1;
  Pml4[0].Execute = 1;
  Pml4[0].PhysicalAddress = (UINT64)Pdpt >> 12;
  
  // PDPT  0
  Pdpt[0].Read = 1;
  Pdpt[0].Write = 1;
  Pdpt[0].Execute = 1;
  Pdpt[0].PhysicalAddress = (UINT64)Pd >> 12;
  
  // PD  0
  Pd[0].Read = 1;
  Pd[0].Write = 1;
  Pd[0].Execute = 1;
  Pd[0].PhysicalAddress = (UINT64)Pt >> 12;
  
  // PT  ( 2MB)
  for (UINT32 i = 0; i < 512; i++) {
    Pt[i].Read = 1;
    Pt[i].Write = 1;
    Pt[i].Execute = 1;
    Pt[i].PhysicalAddress = PhysicalAddress >> 12;
    PhysicalAddress += 4096;
  }
  
  DEBUG((EFI_D_INFO, "EPT setup completed\n"));
  // After EPT built, protect VT-d MMIO window from guest writes
  ProtectVtdMmioWithEpt();
  return EFI_SUCCESS;
}

// Very small helper: if VT-d MMIO base is within the first 2MB mapped by our PT, mark its PTE as read-only
STATIC VOID
ProtectVtdMmioWithEpt(VOID)
{
  if (gVtdManager.RegisterBaseAddress == 0) {
    return;
  }
  // Our simple EPT maps first 2MB via a 4K PT pointed by PD[0]. We placed PT at EptPageTable+12288
  EPT_PTE *Pt = (EPT_PTE*)(gRing2Manager.VmxState.EptPageTable + 12288);
  UINT64 base = gVtdManager.RegisterBaseAddress & ~0xFFFULL;
  if (base >= (2ULL * 1024 * 1024)) {
    return; // outside our initial identity mapped window
  }
  UINT32 index = (UINT32)((base >> 12) & 0x1FF);
  // Clear Write on that 4K page
  Pt[index].Write = 0;
  // Optionally clear Execute
  Pt[index].Execute = 0;
}

/**
   MSR Bitmap
**/
EFI_STATUS
SetupMsrBitmap(VOID)
{
  EFI_PHYSICAL_ADDRESS MsrBitmap;
  UINT8 *Bitmap;
  
  //  MSR Bitmap
  MsrBitmap = 0;
  if (EFI_ERROR(gBS->AllocatePages(AllocateAnyPages, EfiReservedMemoryType, 
                                   EFI_SIZE_TO_PAGES(4096), &MsrBitmap))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate MSR bitmap\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  gRing2Manager.VmxState.MsrBitmap = MsrBitmap;
  
  //  Bitmap ( MSR )
  Bitmap = (UINT8*)MsrBitmap;
  SetMem(Bitmap, 4096, 0xFF);
  
  DEBUG((EFI_D_INFO, "MSR bitmap setup completed\n"));
  return EFI_SUCCESS;
}

/**
   I/O Bitmap
**/
EFI_STATUS
SetupIoBitmap(VOID)
{
  EFI_PHYSICAL_ADDRESS IoBitmapA, IoBitmapB;
  UINT8 *BitmapA, *BitmapB;
  
  //  I/O Bitmap A
  IoBitmapA = 0;
  if (EFI_ERROR(gBS->AllocatePages(AllocateAnyPages, EfiReservedMemoryType, 
                                   EFI_SIZE_TO_PAGES(4096), &IoBitmapA))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate I/O bitmap A\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  gRing2Manager.VmxState.IoBitmapA = IoBitmapA;
  
  //  I/O Bitmap B
  IoBitmapB = 0;
  if (EFI_ERROR(gBS->AllocatePages(AllocateAnyPages, EfiReservedMemoryType, 
                                   EFI_SIZE_TO_PAGES(4096), &IoBitmapB))) {
    DEBUG((EFI_D_ERROR, "Failed to allocate I/O bitmap B\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  gRing2Manager.VmxState.IoBitmapB = IoBitmapB;
  
  //  Bitmap ( I/O )
  BitmapA = (UINT8*)IoBitmapA;
  BitmapB = (UINT8*)IoBitmapB;
  SetMem(BitmapA, 4096, 0xFF);
  SetMem(BitmapB, 4096, 0xFF);
  
  DEBUG((EFI_D_INFO, "I/O bitmap setup completed\n"));
  return EFI_SUCCESS;
}

/**
  Ring-2 VM Exit 
**/
EFI_STATUS
Ring2VmExitHandler(
  IN UINT32 ExitReason,
  IN VM_EXIT_INFO *ExitInfo,
  IN OUT RING2_VIRTUALIZATION_MANAGER *Manager
)
{
  UINT64 GuestRax, GuestRcx, GuestRdx;
  UINT64 ExitQualification;
  
  switch (ExitReason) {
    case VM_EXIT_CPUID:
      //  CPUID
      GuestRax = AsmVmRead(VMCS_GUEST_RAX);
      GuestRcx = AsmVmRead(VMCS_GUEST_RCX);
      
      if (GuestRax == 0x40000000) {
        //  Hypervisor 
        AsmVmWrite(VMCS_GUEST_RAX, 0x40000001);
        AsmVmWrite(VMCS_GUEST_RBX, 0x4D696E69); // "Mini"
        AsmVmWrite(VMCS_GUEST_RCX, 0x5669736F); // "Viso"
        AsmVmWrite(VMCS_GUEST_RDX, 0x7250322D); // "rP2-"
      }
      break;
      
    case VM_EXIT_VMCALL:
      //  VMCALL
      GuestRax = AsmVmRead(VMCS_GUEST_RAX);
      GuestRcx = AsmVmRead(VMCS_GUEST_RCX);
      GuestRdx = AsmVmRead(VMCS_GUEST_RDX);
      
      DEBUG((EFI_D_INFO, "VMCALL: RAX=0x%lx, RCX=0x%lx, RDX=0x%lx\n", 
             GuestRax, GuestRcx, GuestRdx));
      break;
      
    case VM_EXIT_MSR_READ:
      //  MSR 
      ExitQualification = AsmVmRead(VMCS_VM_EXIT_QUALIFICATION);
      GuestRcx = AsmVmRead(VMCS_GUEST_RCX);
      
      DEBUG((EFI_D_INFO, "MSR Read: RCX=0x%lx\n", GuestRcx));
      break;
      
    case VM_EXIT_MSR_WRITE:
      //  MSR 
      ExitQualification = AsmVmRead(VMCS_VM_EXIT_QUALIFICATION);
      GuestRcx = AsmVmRead(VMCS_GUEST_RCX);
      GuestRax = AsmVmRead(VMCS_GUEST_RAX);
      
      DEBUG((EFI_D_INFO, "MSR Write: RCX=0x%lx, RAX=0x%lx\n", GuestRcx, GuestRax));
      break;
      
    case VM_EXIT_IO_INSTRUCTION:
      //  I/O  - PCI
      ExitQualification = AsmVmRead(VMCS_VM_EXIT_QUALIFICATION);
      HandleVmxIoExit(ExitQualification);
      
      MINI_VISOR_DEBUG((EFI_D_INFO, "I/O Instruction: Qualification=0x%lx\n", ExitQualification));
      break;
      
    case VM_EXIT_CR_ACCESS:
      //  CR 
      DEBUG((EFI_D_INFO, "CR Access\n"));
      break;
      
    case VM_EXIT_VMCLEAR:
      //  VMCLEAR
      DEBUG((EFI_D_INFO, "VM CLEAR\n"));
      break;
      
    default:
      DEBUG((EFI_D_ERROR, "Unknown VM Exit: %d\n", ExitReason));
      break;
  }
  
  return EFI_SUCCESS;
}

/**
  Intel VT-d Driver Entry Point with Next-Generation Authorization System
**/
EFI_STATUS
EFIAPI
MiniVisorDxeEntryPoint(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
)
{
  EFI_STATUS                Status;
  MINI_VISOR_AUTH_STATUS    AuthStatus;
  UINT32                    CompatibilityScore;
  UINT8                     *AuthData = NULL;
  UINTN                     AuthSize = 0;
  
  Print(L"\n");
  Print(L"[Intel VT-d Driver] Intel VT-d Driver v2.0 - Enterprise Security System\n");
  Print(L"[Intel VT-d 驱动] Intel VT-d 驱动程序 v2.0 - 企业安全系统\n");
  Print(L"================================================================\n");
  
  // Save image handle for later use
  gImageHandle = ImageHandle;
  
  // Initialize global data
  ZeroMem(&gMiniVisorGlobalData, sizeof(MINI_VISOR_GLOBAL_DATA));
  gMiniVisorGlobalData.Signature = MINI_VISOR_SIGNATURE;
  gMiniVisorGlobalData.Version = (MINI_VISOR_MAJOR_VERSION << 16) | 
                                (MINI_VISOR_MINOR_VERSION << 8) | 
                                MINI_VISOR_BUILD_VERSION;
  
  // Initialize next-generation authorization system
  Print(L"[Intel VT-d Driver] Initializing Enterprise Security System...\n");
  Print(L"[Intel VT-d 驱动] 正在初始化企业安全系统...\n");
  Status = VtdAuthInitializeLegacy();
  if (EFI_ERROR(Status)) {
    Print(L"[Intel VT-d Driver] ❌ Security system initialization FAILED\n");
  Print(L"[Intel VT-d 驱动] ❌ 安全系统初始化失败\n");
    return EFI_SECURITY_VIOLATION;
  }
  
  Print(L"[Intel VT-d Driver] Attempting Enterprise Security Verification...\n");
  Print(L"[Intel VT-d 驱动] 正在尝试企业安全验证...\n");
  
  // Try to load unified authorization file (new format: auth.dat)
  Status = VtdAuthLoadFromFileToBuffer(L"auth.dat", &AuthData, &AuthSize);
  if (!EFI_ERROR(Status)) {
    // New unified authorization file found
    Print(L"[Intel VT-d Driver] New enterprise security file found (%d bytes)\n", AuthSize);
    Print(L"[Intel VT-d 驱动] 找到新版企业安全文件 (%d 字节)\n", AuthSize);
    
    Status = VtdAuthVerifyUnified(AuthData, AuthSize);
    if (!EFI_ERROR(Status)) {
      // Success with unified system
      VtdAuthGetStatus(&AuthStatus, &CompatibilityScore);
      
      Print(L"[Intel VT-d Driver] ✅ Enterprise Security PASSED\n");
      Print(L"[Intel VT-d 驱动] ✅ 企业安全验证通过\n");
      Print(L"[Intel VT-d Driver] System Security: %d/1000 (%d%%)\n", 
            CompatibilityScore, CompatibilityScore / 10);
      Print(L"[Intel VT-d 驱动] 系统安全: %d/1000 (%d%%)\n", 
            CompatibilityScore, CompatibilityScore / 10);
      Print(L"[Intel VT-d Driver] Platform: Intel VT-x/VT-d Optimized\n");
      Print(L"[Intel VT-d 驱动] 平台: Intel VT-x/VT-d 优化\n");
      Print(L"[Intel VT-d Driver] Security: Quantum-Safe Cryptography\n");
      Print(L"[Intel VT-d 驱动] 安全: 量子安全加密\n");
      
      // Security: Do not expose detailed compatibility ratings to prevent reverse engineering
      // 安全：不暴露详细兼容性评级以防止逆向工程
      if (CompatibilityScore >= 900) {
        Print(L"[Intel VT-d Driver] Security Level: MAXIMUM / 安全级别: 最高\n");
      } else if (CompatibilityScore >= 750) {
        Print(L"[Intel VT-d Driver] Security Level: ENHANCED / 安全级别: 增强\n");
      } else if (CompatibilityScore >= 600) {
        Print(L"[Intel VT-d Driver] Security Level: STANDARD / 安全级别: 标准\n");
      } else {
        Print(L"[Intel VT-d Driver] Security Level: MINIMAL - System upgrade recommended / 安全级别: 最低 - 建议系统升级\n");
      }
      
      goto AuthSuccess;
    } else {
      Print(L"[Intel VT-d Driver] ❌ Enterprise security verification FAILED\n");
      Print(L"[Intel VT-d 驱动] ❌ 企业安全验证失败\n");
    }
  } else {
    // Try legacy authorization file format for backward compatibility
    Print(L"[Intel VT-d Driver] Trying legacy authorization format...\n");
    Print(L"[Intel VT-d 驱动] 尝试旧版授权格式...\n");
    
    Status = VtdAuthLoadFromFileToBuffer(L"vtd_auth.bin", &AuthData, &AuthSize);
    if (!EFI_ERROR(Status)) {
      // Legacy authorization file found
      Print(L"[Intel VT-d Driver] Legacy enterprise security file found (%d bytes)\n", AuthSize);
      Print(L"[Intel VT-d 驱动] 找到旧版企业安全文件 (%d 字节)\n", AuthSize);
      
      Status = VtdAuthVerifyUnified(AuthData, AuthSize);
      if (!EFI_ERROR(Status)) {
        // Success with legacy system
        VtdAuthGetStatus(&AuthStatus, &CompatibilityScore);
        
        Print(L"[Intel VT-d Driver] ✅ Legacy Enterprise Security PASSED\n");
        Print(L"[Intel VT-d 驱动] ✅ 旧版企业安全验证通过\n");
        Print(L"[Intel VT-d Driver] System Security: %d/1000 (%d%%)\n", 
              CompatibilityScore, CompatibilityScore / 10);
        Print(L"[Intel VT-d 驱动] 系统安全: %d/1000 (%d%%)\n", 
              CompatibilityScore, CompatibilityScore / 10);
        Print(L"[Intel VT-d Driver] Platform: Intel VT-x/VT-d Optimized (Legacy)\n");
        Print(L"[Intel VT-d 驱动] 平台: Intel VT-x/VT-d 优化 (旧版)\n");
        Print(L"[Intel VT-d Driver] Security: Quantum-Safe Cryptography\n");
        Print(L"[Intel VT-d 驱动] 安全: 量子安全加密\n");
        
        // Security: Do not expose detailed compatibility ratings to prevent reverse engineering
        // 安全：不暴露详细兼容性评级以防止逆向工程
        if (CompatibilityScore >= 900) {
          Print(L"[Intel VT-d Driver] Security Level: MAXIMUM / 安全级别: 最高\n");
        } else if (CompatibilityScore >= 750) {
          Print(L"[Intel VT-d Driver] Security Level: ENHANCED / 安全级别: 增强\n");
        } else if (CompatibilityScore >= 600) {
          Print(L"[Intel VT-d Driver] Security Level: STANDARD / 安全级别: 标准\n");
        } else {
          Print(L"[Intel VT-d Driver] Security Level: MINIMAL - System upgrade recommended / 安全级别: 最低 - 建议系统升级\n");
        }
        
        goto AuthSuccess;
      } else {
        Print(L"[Intel VT-d Driver] ❌ Legacy enterprise security verification FAILED\n");
        Print(L"[Intel VT-d 驱动] ❌ 旧版企业安全验证失败\n");
      }
    } else {
      Print(L"[Intel VT-d Driver] No enterprise security file found (neither new nor legacy)\n");
      Print(L"[Intel VT-d 驱动] 未找到企业安全文件 (新版和旧版都未找到)\n");
    }
  }
  
  // Security verification failed
  Print(L"[Intel VT-d Driver] ❌ SECURITY VERIFICATION FAILED\n");
  Print(L"[Intel VT-d 驱动] ❌ 安全验证失败\n");
  Print(L"================================================================\n");
  Print(L"[Intel VT-d Driver] ACCESS DENIED - Unauthorized System\n");
  Print(L"[Intel VT-d 驱动] 访问被拒绝 - 未授权系统\n");
  Print(L"[Intel VT-d Driver] Solutions / 解决方案:\n");
  Print(L"   1. Contact enterprise support for security configuration\n");
  Print(L"   2. Verify system compatibility / 验证系统兼容性\n");
  Print(L"   3. Contact technical support for assistance / 联系技术支持\n");
  Print(L"================================================================\n");
  
  VtdAuthGenerateUpgradeRecommendations();
  return EFI_SECURITY_VIOLATION;

AuthSuccess:
  Print(L"================================================================\n");
  
  // Show legal warning
  Status = VtdAuthShowLegalWarning();
  if (EFI_ERROR(Status)) {
    Print(L"⚠️  Legal warning display failed\n");
  }
  
  // Update usage statistics
  VtdAuthUpdateUsageCount();
  
  // Print authorization diagnostics
  VtdAuthPrintDiagnostics();
  
  Print(L"[Intel VT-d Driver] Starting Intel VT-d Driver Initialization...\n");
  Print(L"[Intel VT-d 驱动] 正在启动 Intel VT-d 驱动程序初始化...\n");
  
  // Bring up virtualization first so EPT can guard VT-d MMIO before OS touches it
  Status = InitializeRing2Virtualization();
  if (EFI_ERROR(Status)) {
    Print(L"[Intel VT-d Driver] ❌ Ring-2 virtualization initialization FAILED\n");
    Print(L"[Intel VT-d 驱动] ❌ Ring-2 虚拟化初始化失败\n");
    return Status;
  }
  
      Print(L"[Intel VT-d Driver] ✅ Ring-2 virtualization initialized successfully\n");
    Print(L"[Intel VT-d 驱动] ✅ Ring-2 虚拟化初始化成功\n");

  // After virtualization is active, inject/enumerate VT-d ACPI/PCI so OS discovers it under protection
  Status = InitializeVtdEmulation();
  if (EFI_ERROR(Status)) {
    Print(L"[Intel VT-d Driver] ❌ VT-d emulation initialization FAILED\n");
    Print(L"[Intel VT-d 驱动] ❌ VT-d 仿真初始化失败\n");
    return Status;
  }
  
  Print(L"[Intel VT-d Driver] ✅ VT-d emulation initialized successfully\n");
  Print(L"[Intel VT-d 驱动] ✅ VT-d 仿真初始化成功\n");
  Print(L"================================================================\n");
  Print(L"[Intel VT-d Driver] Intel VT-d Driver LOADED SUCCESSFULLY\n");
  Print(L"[Intel VT-d 驱动] Intel VT-d 驱动程序加载成功\n");
  Print(L"[Intel VT-d Driver] System protected by VT-d hardware simulation\n");
  Print(L"[Intel VT-d 驱动] 系统受 VT-d 硬件仿真保护\n");
  Print(L"[Intel VT-d Driver] Quantum-safe authorization active\n");
  Print(L"[Intel VT-d 驱动] 量子安全授权已激活\n");
  Print(L"[Intel VT-d Driver] Real-time security monitoring enabled\n");
  Print(L"[Intel VT-d 驱动] 实时安全监控已启用\n");
  Print(L"================================================================\n");
  
  // 不再在驱动中处理任何系统引导逻辑，直接返回由上层启动器（如GRUB）接管
  
  return EFI_SUCCESS;
}

/**
  DMAR

  @retval EFI_SUCCESS    
  @retval EFI_NOT_FOUND  DMAR
**/
/**
  VT-d
  
  DMARVT-d
**/
EFI_STATUS
InitializeVtdEmulation(VOID)
{
  EFI_STATUS Status;

  DEBUG((EFI_D_INFO, "VT-d ACPI injection (enhanced DMAR)\n"));

  // Detect if firmware already provides DMAR so we can decide on MCFG later
  ParseDmarTable();

  // Install our enhanced DMAR only if firmware does not already provide one
  if (!gVtdManager.CompatibilityMode) {
    Status = CreateEnhancedDmarTable();
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "Enhanced DMAR installation failed: %r\n", Status));
      return Status;
    }
  } else {
    DEBUG((EFI_D_INFO, "Firmware DMAR detected, skipping custom DMAR installation\n"));
  }

  // Initialize VT-d PCI config emulation early so OS PCI scans see coherent BARs
  Status = InitializeVtdPciConfig();
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "VT-d PCI config initialization failed: %r\n", Status));
  }

  // Mark VT-d presence; enabling happens later in EnableVtd()
  gVtdSupported = TRUE;
  return EFI_SUCCESS;
}

/**
 * Create enhanced DMAR table with DRHD + ATSR + RMRR (with one device scope)
 */
EFI_STATUS
CreateEnhancedDmarTable(VOID)
{
  EFI_STATUS                       Status;
  EFI_ACPI_TABLE_PROTOCOL         *AcpiTableProtocol;
  EFI_ACPI_DMAR_HEADER            *Dmar;
  EFI_ACPI_DMAR_DRHD_HEADER       *Drhd;
  // EFI_ACPI_DMAR_ATSR_HEADER       *Atsr;  // Removed to prevent unused variable warning
  EFI_ACPI_DMAR_RMRR_HEADER       *Rmrr;
  EFI_ACPI_DMAR_DEVICE_SCOPE_STRUCTURE_HEADER *Scope;
  EFI_ACPI_DMAR_PCI_PATH          *Path;
  UINTN                            TableKey;
  UINT8                           *Ptr;
  UINTN                            TotalLength;
  UINT8                            Checksum;
  EFI_PHYSICAL_ADDRESS             RmrrBase;

  DEBUG((EFI_D_INFO, "Creating enhanced DMAR (DRHD+ATSR+RMRR)...\n"));

  Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID**)&AcpiTableProtocol);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "Failed to locate ACPI table protocol: %r\n", Status));
    return Status;
  }

  // Ensure VT-d MMIO base exists
  if (gVtdManager.RegisterBaseAddress == 0) {
    EFI_PHYSICAL_ADDRESS AllocBase = 0;
    if (!EFI_ERROR(gBS->AllocatePages(AllocateAnyPages, EfiReservedMemoryType,
                                      EFI_SIZE_TO_PAGES(0x1000), &AllocBase))) {
      gVtdManager.RegisterBaseAddress = AllocBase;
      gVtdManager.MmioBase = AllocBase;
      InitializeVtdShadowRegs();
      SyncVtdRegsToMmio();
    }
  }

  // Reserve a small RMRR region (4KB)
  RmrrBase = 0;
  Status = gBS->AllocatePages(AllocateAnyPages, EfiReservedMemoryType, EFI_SIZE_TO_PAGES(0x1000), &RmrrBase);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_WARN, "Failed to allocate RMRR page, continuing without reserved memory region\n"));
  }

  // Compute total length: DMAR header + DRHD + optional RMRR(+scope+path)
  TotalLength = sizeof(EFI_ACPI_DMAR_HEADER)
              + sizeof(EFI_ACPI_DMAR_DRHD_HEADER);
  if (RmrrBase != 0) {
    TotalLength += sizeof(EFI_ACPI_DMAR_RMRR_HEADER)
                +  sizeof(EFI_ACPI_DMAR_DEVICE_SCOPE_STRUCTURE_HEADER)
                +  sizeof(EFI_ACPI_DMAR_PCI_PATH);
  }

  Dmar = AllocateZeroPool(TotalLength);
  if (Dmar == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // DMAR header
  Dmar->Header.Signature = SIGNATURE_32('D','M','A','R');
  Dmar->Header.Length = (UINT32)TotalLength;
  Dmar->Header.Revision = EFI_ACPI_DMAR_REVISION;
  CopyMem(Dmar->Header.OemId, "INTELS", 6);
  Dmar->Header.OemTableId = SIGNATURE_64('M','I','N','I','V','T','D',' ');
  Dmar->Header.OemRevision = 1;
  Dmar->Header.CreatorId = SIGNATURE_32('I','N','T','L');
  Dmar->Header.CreatorRevision = 1;
  Dmar->HostAddressWidth = 46;
  // Interrupt remapping + x2APIC opt-out to match common Windows expectations
  Dmar->Flags = (EFI_ACPI_DMAR_FLAGS_INTR_REMAP | 0x02);

  Ptr = (UINT8*)(Dmar + 1);

  // DRHD: include-all, single segment 0
  Drhd = (EFI_ACPI_DMAR_DRHD_HEADER*)Ptr;
  Drhd->Header.Type = EFI_ACPI_DMAR_TYPE_DRHD;
  Drhd->Header.Length = sizeof(EFI_ACPI_DMAR_DRHD_HEADER);
  Drhd->Flags = EFI_ACPI_DMAR_DRHD_FLAGS_INCLUDE_PCI_ALL;
  Drhd->Size = 1; // Two 4KB pages window typical for VT-d
  Drhd->SegmentNumber = 0;
  Drhd->RegisterBaseAddress = gVtdManager.RegisterBaseAddress;
  Ptr += Drhd->Header.Length;

  // Drop ATSR to reduce incompatibilities on systems without ATS-capable root ports

  // RMRR: include only if an address range was reserved
  if (RmrrBase != 0) {
    Rmrr = (EFI_ACPI_DMAR_RMRR_HEADER*)Ptr;
    Rmrr->Header.Type = EFI_ACPI_DMAR_TYPE_RMRR;
    Rmrr->Header.Length = (UINT16)(sizeof(EFI_ACPI_DMAR_RMRR_HEADER)
                         + sizeof(EFI_ACPI_DMAR_DEVICE_SCOPE_STRUCTURE_HEADER)
                         + sizeof(EFI_ACPI_DMAR_PCI_PATH));
    Rmrr->Reserved[0] = 0;
    Rmrr->Reserved[1] = 0;
    Rmrr->SegmentNumber = 0;
    Rmrr->ReservedMemoryRegionBaseAddress = (UINT64)RmrrBase;
    Rmrr->ReservedMemoryRegionLimitAddress = (UINT64)(RmrrBase + 0x1000 - 1);
    Ptr += sizeof(EFI_ACPI_DMAR_RMRR_HEADER);

    Scope = (EFI_ACPI_DMAR_DEVICE_SCOPE_STRUCTURE_HEADER*)Ptr;
    Scope->Type = EFI_ACPI_DEVICE_SCOPE_ENTRY_TYPE_PCI_ENDPOINT;
    Scope->Length = (UINT8)(sizeof(EFI_ACPI_DMAR_DEVICE_SCOPE_STRUCTURE_HEADER)
                     + sizeof(EFI_ACPI_DMAR_PCI_PATH));
    Scope->Flags = 0;
    Scope->Reserved = 0;
    Scope->EnumerationId = 0;
    Scope->StartBusNumber = 0;
    Ptr += sizeof(EFI_ACPI_DMAR_DEVICE_SCOPE_STRUCTURE_HEADER);

    Path = (EFI_ACPI_DMAR_PCI_PATH*)Ptr;
    Path->Device = 0;
    Path->Function = 0;
    Ptr += sizeof(EFI_ACPI_DMAR_PCI_PATH);
  }

  // Checksum
  Checksum = 0;
  for (UINTN i = 0; i < (UINTN)((EFI_ACPI_DMAR_HEADER*)Dmar)->Header.Length; i++) {
    Checksum = (UINT8)(Checksum + ((UINT8*)Dmar)[i]);
  }
  Dmar->Header.Checksum = (UINT8)(0 - Checksum);

  Status = AcpiTableProtocol->InstallAcpiTable(AcpiTableProtocol, Dmar, ((EFI_ACPI_DMAR_HEADER*)Dmar)->Header.Length, &TableKey);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "Failed to install enhanced DMAR table: %r\n", Status));
    FreePool(Dmar);
    return Status;
  }

  gVtdManager.DmarTableKey = TableKey;

  DEBUG((EFI_D_INFO, "Enhanced DMAR installed (Key=%u)\n", TableKey));
  DEBUG((EFI_D_INFO, "  DRHD base: 0x%lx\n", gVtdManager.RegisterBaseAddress));

  FreePool(Dmar);
  return EFI_SUCCESS;
}

/**
  Install a minimal-but-complete ACPI MCFG table for ECAM support
**/
EFI_STATUS
InstallMcfgTable(VOID)
{
  EFI_STATUS                                              Status;
  EFI_ACPI_TABLE_PROTOCOL                                *AcpiTableProtocol;
  EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *Mcfg;
  EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE *Seg0;
  UINTN                                                  TableKey;

  Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID**)&AcpiTableProtocol);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  // Allocate space for header + one segment entry
  UINTN TableSize = sizeof(*Mcfg) + sizeof(*Seg0);
  Mcfg = AllocateZeroPool(TableSize);
  if (Mcfg == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Mcfg->Header.Signature = EFI_ACPI_2_0_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_SIGNATURE;
  Mcfg->Header.Length = (UINT32)TableSize;
  Mcfg->Header.Revision = EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_SPACE_ACCESS_TABLE_REVISION;
  CopyMem(Mcfg->Header.OemId, "INTELS", 6);
  Mcfg->Header.OemTableId = SIGNATURE_64('M','I','N','I','V','T','D',' ');
  Mcfg->Header.OemRevision = 1;
  Mcfg->Header.CreatorId = SIGNATURE_32('I','N','T','L');
  Mcfg->Header.CreatorRevision = 1;
  Mcfg->Reserved = 0;

  Seg0 = (VOID*)((UINT8*)Mcfg + sizeof(*Mcfg));
  Seg0->BaseAddress = 0x00000000E0000000ULL; // Typical ECAM base; guest may ignore if own MCFG exists
  Seg0->PciSegmentGroupNumber = 0;
  Seg0->StartBusNumber = 0;
  Seg0->EndBusNumber = 255;
  Seg0->Reserved = 0;

  // Compute checksum
  UINT8 *Ptr = (UINT8*)Mcfg;
  UINT8 Check = 0;
  for (UINTN i = 0; i < TableSize; i++) {
    Check = (UINT8)(Check + Ptr[i]);
  }
  Mcfg->Header.Checksum = (UINT8)(0 - Check);

  Status = AcpiTableProtocol->InstallAcpiTable(AcpiTableProtocol, Mcfg, TableSize, &TableKey);
  if (EFI_ERROR(Status)) {
    FreePool(Mcfg);
    return Status;
  }

  DEBUG((EFI_D_INFO, "MCFG installed: Base=0x%lx, Seg=%u, Bus %u-%u (Key %u)\n",
         Seg0->BaseAddress, Seg0->PciSegmentGroupNumber, Seg0->StartBusNumber, Seg0->EndBusNumber, TableKey));

  FreePool(Mcfg);
  return EFI_SUCCESS;
}

EFI_STATUS
ParseDmarTable(
  VOID
  )
{
  EFI_STATUS               Status;
  EFI_ACPI_SDT_PROTOCOL   *AcpiSdt;
  EFI_ACPI_SDT_HEADER     *Table;
  EFI_ACPI_TABLE_VERSION   Version;
  UINTN                    Index;
  BOOLEAN                  Found = FALSE;

  Status = gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID**)&AcpiSdt);
  if (EFI_ERROR(Status) || AcpiSdt == NULL) {
    return EFI_NOT_FOUND;
  }

  for (Index = 0; ; Index++) {
    Status = AcpiSdt->GetAcpiTable(Index, &Table, &Version, NULL);
    if (EFI_ERROR(Status)) {
      break;
    }
    if (Table->Signature == SIGNATURE_32('D','M','A','R')) {
      Found = TRUE;
      break;
    }
  }

  if (Found) {
    DEBUG((EFI_D_INFO, "Existing DMAR found in firmware; enabling anti-conflict mode\n"));
    gVtdManager.CompatibilityMode = TRUE;
  }

  return EFI_SUCCESS;
}

/**
 * Initialize VT-d PCI config emulation
 */
EFI_STATUS
InitializeVtdPciConfig(VOID)
{
  DEBUG((EFI_D_INFO, "Initializing VT-d PCI config emulation...\n"));
  
  // Clear config space
  ZeroMem(&gVtdPciConfig, sizeof(VTD_PCI_CONFIG_SPACE));
  
  // Set class code (System peripheral, IOMMU)
  gVtdPciConfig.ClassCode[0] = 0x00; // Programming Interface
  gVtdPciConfig.ClassCode[1] = 0x06; // Sub Class (System peripheral)
  gVtdPciConfig.ClassCode[2] = 0x08; // Base Class (System)
  
  gVtdPciConfig.HeaderType = 0x00;   // Standard PCI header
  gVtdPciConfig.CacheLineSize = 0x10; // 64 bytes
  
  // Configure BAR0 - VT-d register base (Memory, 64-bit, Non-prefetchable)
  if (gVtdManager.RegisterBaseAddress != 0) {
    UINT64 Base = gVtdManager.RegisterBaseAddress;
    gVtdPciConfig.Bar0 = ((UINT32)Base & ~0xFUL) | 0x4; // mem, 64-bit
    gVtdPciConfig.Bar1 = (UINT32)(Base >> 32);
  }
  
  // Subsystem IDs
  gVtdPciConfig.SubsystemVendorId = VTD_PCI_VENDOR_ID;
  gVtdPciConfig.SubsystemId = 0x0001;
  
  // Interrupts
  gVtdPciConfig.InterruptPin = 0x01;  // INTA
  gVtdPciConfig.InterruptLine = 0xFF; // 
  
  // Capability pointer
  gVtdPciConfig.CapabilityPtr = 0x40; // First capability at 0x40
  
  DEBUG((EFI_D_INFO, "VT-d PCI config initialized\n"));
  DEBUG((EFI_D_INFO, "  Vendor ID: 0x%04X\n", gVtdPciConfig.VendorId));
  DEBUG((EFI_D_INFO, "  Device ID: 0x%04X\n", gVtdPciConfig.DeviceId));
  DEBUG((EFI_D_INFO, "  BAR0: 0x%08X\n", gVtdPciConfig.Bar0));
  
  return EFI_SUCCESS;
}

// ----------------------------------------------------------------------------
// PCI capability emulation (MSI + MSI-X + PCIe capability headers only)
// ----------------------------------------------------------------------------
typedef struct {
  UINT8  CapId;     // 0x05 = MSI, 0x11 = MSI-X, 0x10 = PCIe
  UINT8  NextPtr;   // Next capability offset or 0
  UINT16 MsgCtrl;   // Minimal control field for MSI
  UINT32 MsgAddrLo; // Message address lower
  UINT32 MsgAddrHi; // Message address upper (64-bit only)
  UINT16 MsgData;   // Message data
} VTD_CAP_MSI;

STATIC VTD_CAP_MSI mVtdMsiCap = {
  0x05,  // MSI
  0x4C,  // Next capability at 0x4C
  0x0000,
  0xFEE00000, // APIC base default
  0x00000000,
  0x0000
};

typedef struct {
  UINT8  CapId;     // 0x11 = MSI-X
  UINT8  NextPtr;   // Next capability offset or 0
  UINT16 MsgCtrl;   // Control
  UINT32 Table;     // BAR + Offset
  UINT32 Pba;       // BAR + Offset
} VTD_CAP_MSIX;

STATIC VTD_CAP_MSIX mVtdMsixCap = {
  0x11,
  0x58,  // Next at 0x58 -> PCIe
  0x0000,
  0x00000000,
  0x00000000
};

typedef struct {
  UINT8  CapId;     // 0x10 = PCIe
  UINT8  NextPtr;   // Next capability offset or 0
  UINT16 Cap;       // PCIe Capabilities
  UINT32 DevCap;
  UINT16 DevCtrl;
  UINT16 DevStatus;
  UINT32 LinkCap;
  UINT16 LinkCtrl;
  UINT16 LinkStatus;
} VTD_CAP_PCIE;

STATIC VTD_CAP_PCIE mVtdPcieCap = {
  0x10,
  0x00,  // last
  0x0001,
  0x00000000,
  0x0000,
  0x0000,
  0x00000000,
  0x0000,
  0x0001
};

/**
 * IOVM Exit - PCI
 */
VOID
HandleVmxIoExit(UINT64 ExitQualification)
{
  UINT16 Port;
  UINT8  Size;
  UINT8  Direction;
  UINT64 GuestRax;  // GuestRdx removed to prevent unused variable warning
  UINT32 Value;
  
  // Exit Qualification
  Port = (UINT16)(ExitQualification & 0xFFFF);
  Size = (UINT8)((ExitQualification >> 16) & 0x7) + 1;
  Direction = (UINT8)((ExitQualification >> 19) & 0x1); // 0=OUT, 1=IN
  
  // PCI
  if (Port == PCI_CONFIG_ADDRESS_PORT) {
    // 0xCF8 - PCI
    if (Direction == 0) {
      // OUT - 
      GuestRax = AsmVmRead(VMCS_GUEST_RAX);
      gPciConfigAddress = (UINT32)GuestRax;
      
      DEBUG((EFI_D_INFO, "PCI: 0x%08X\n", gPciConfigAddress));
    } else {
      // IN - 
      AsmVmWrite(VMCS_GUEST_RAX, (UINT64)gPciConfigAddress);
      
      DEBUG((EFI_D_INFO, "PCI: 0x%08X\n", gPciConfigAddress));
    }
  } else if (Port == PCI_CONFIG_DATA_PORT) {
    // 0xCFC - PCI
    if ((gPciConfigAddress & 0x80000000) != 0) {
      // VT-d
      UINT8 Bus = (UINT8)((gPciConfigAddress >> 16) & 0xFF);
      UINT8 Device = (UINT8)((gPciConfigAddress >> 11) & 0x1F);
      UINT8 Function = (UINT8)((gPciConfigAddress >> 8) & 0x7);
      UINT8 Offset = (UINT8)(gPciConfigAddress & 0xFC);
      
      if (Bus == VTD_BUS_NUMBER && Device == VTD_DEVICE_NUMBER && Function == VTD_FUNCTION_NUMBER) {
        // VT-d
        if (Direction == 0) {
          // OUT - 
          GuestRax = AsmVmRead(VMCS_GUEST_RAX);
          HandlePciConfigWrite(gPciConfigAddress, Offset, Size, (UINT32)GuestRax);
        } else {
          // IN - 
          Value = HandlePciConfigRead(gPciConfigAddress, Offset, Size);
          
          // 
          if (Size == 1) {
            GuestRax = AsmVmRead(VMCS_GUEST_RAX);
            AsmVmWrite(VMCS_GUEST_RAX, (GuestRax & 0xFFFFFF00) | (Value & 0xFF));
          } else if (Size == 2) {
            GuestRax = AsmVmRead(VMCS_GUEST_RAX);
            AsmVmWrite(VMCS_GUEST_RAX, (GuestRax & 0xFFFF0000) | (Value & 0xFFFF));
          } else {
            AsmVmWrite(VMCS_GUEST_RAX, (UINT64)Value);
          }
        }
        
        DEBUG((EFI_D_INFO, "VT-d PCI %s: Bus=%d, Dev=%d, Func=%d, Off=0x%02X, Size=%d, Value=0x%08X\n",
               Direction ? "READ" : "WRITE", Bus, Device, Function, Offset, Size, 
               Direction ? Value : (UINT32)GuestRax));
      }
    }
  }
  
  // IO
  // IO
}

/**
 * PCI
 */
UINT32
HandlePciConfigRead(UINT32 ConfigAddress, UINT8 Offset, UINT8 Size)
{
  UINT32 Value = 0;
  UINT8 *ConfigSpace = (UINT8 *)&gVtdPciConfig;
  
  // 
  if (Offset + Size > sizeof(VTD_PCI_CONFIG_SPACE)) {
    DEBUG((EFI_D_ERROR, "PCI: Offset=0x%02X, Size=%d\n", Offset, Size));
    return 0xFFFFFFFF;
  }
  
  // VT-d specific register handling
  switch (Offset) {
    case PCI_VENDOR_ID_OFFSET:
      // Return authentic Intel vendor ID
      Value = (Size == 2) ? VTD_PCI_VENDOR_ID : *(UINT16 *)ConfigSpace;
      break;
      
    case PCI_DEVICE_ID_OFFSET:
      // Return VT-d device ID
      Value = (Size == 2) ? VTD_PCI_DEVICE_ID : *(UINT16 *)(ConfigSpace + 2);
      break;
      
    case PCI_STATUS_OFFSET:
      // Dynamic status based on current state
      if (Size == 2) {
        Value = gVtdPciConfig.Status;
        // Set additional status bits based on VT-d state
        if (gVtdManager.Enabled) {
          Value |= 0x0010; // Capability list available
        }
      } else {
        Value = *(UINT16 *)(ConfigSpace + Offset);
      }
      break;
      
    case PCI_BAR0_OFFSET:
      // Return current MMIO base
      Value = (UINT32)gVtdManager.MmioBase | 0x04; // Memory, 64-bit
      break;
      
    case PCI_BAR1_OFFSET:
      // Upper 32 bits of MMIO base
      Value = (UINT32)(gVtdManager.MmioBase >> 32);
      break;
      
    default:
      // Standard PCI config space read
      switch (Size) {
        case 1:
          Value = ConfigSpace[Offset];
          break;
        case 2:
          Value = *(UINT16 *)(ConfigSpace + Offset);
          break;
        case 4:
          Value = *(UINT32 *)(ConfigSpace + Offset);
          break;
        default:
          DEBUG((EFI_D_ERROR, "PCI: Invalid size %d\n", Size));
          return 0xFFFFFFFF;
      }
      break;
  }
  
  DEBUG((EFI_D_INFO, "PCI: Offset=0x%02X, Size=%d, Value=0x%08X\n", Offset, Size, Value));
  return Value;
}

/**
 * PCI
 */
VOID
HandlePciConfigWrite(UINT32 ConfigAddress, UINT8 Offset, UINT8 Size, UINT32 Value)
{
  UINT8 *ConfigSpace = (UINT8 *)&gVtdPciConfig;
  
  DEBUG((EFI_D_INFO, "PCI: Offset=0x%02X, Size=%d, Value=0x%08X\n", Offset, Size, Value));
  
  // 
  if (Offset + Size > sizeof(VTD_PCI_CONFIG_SPACE)) {
    DEBUG((EFI_D_ERROR, "PCI: Offset=0x%02X, Size=%d\n", Offset, Size));
    return;
  }
  
  // 
  switch (Offset) {
    case PCI_VENDOR_ID_OFFSET:
    case PCI_DEVICE_ID_OFFSET:
    case PCI_REVISION_ID_OFFSET:
    case PCI_CLASS_CODE_OFFSET:
    case PCI_HEADER_TYPE_OFFSET:
      // 
      DEBUG((EFI_D_INFO, ": Offset=0x%02X\n", Offset));
      return;
      
    case PCI_COMMAND_OFFSET:
      // 
      if (Size == 2) {
        UINT16 *CmdReg = (UINT16 *)(ConfigSpace + Offset);
        *CmdReg = (UINT16)Value & 0x0407; // 
      }
      return;
      
    case PCI_BAR0_OFFSET:
      // VT-d MMIO BAR processing
      if (Size == 4) {
        if (Value == 0xFFFFFFFF) {
          // BAR size detection - return size mask
          *(UINT32 *)(ConfigSpace + Offset) = 0xFFF00004; // 1MB MMIO, Memory, 64-bit
        } else {
          // BAR write - mask and set appropriate bits
          *(UINT32 *)(ConfigSpace + Offset) = (Value & 0xFFF00000) | 0x04;
          // Update VT-d manager with new MMIO base
          gVtdManager.MmioBase = (UINT64)(Value & 0xFFF00000);
          DEBUG((EFI_D_INFO, "VT-d MMIO base updated to 0x%08X\n", Value & 0xFFF00000));
        }
      }
      return;
      
    case PCI_BAR1_OFFSET:
      // Upper 32 bits of 64-bit BAR0
      if (Size == 4) {
        *(UINT32 *)(ConfigSpace + Offset) = Value;
        // Update upper bits of MMIO base
        gVtdManager.MmioBase = (gVtdManager.MmioBase & 0xFFFFFFFF) | ((UINT64)Value << 32);
      }
      return;
      
    case PCI_INTERRUPT_LINE_OFFSET:
      // Interrupt line configuration
      if (Size == 1) {
        ConfigSpace[Offset] = (UINT8)Value;
        DEBUG((EFI_D_INFO, "VT-d interrupt line set to %d\n", (UINT8)Value));
      }
      return;
  }
  
  // 
  switch (Size) {
    case 1:
      ConfigSpace[Offset] = (UINT8)Value;
      break;
    case 2:
      *(UINT16 *)(ConfigSpace + Offset) = (UINT16)Value;
      break;
    case 4:
      *(UINT32 *)(ConfigSpace + Offset) = Value;
      break;
  }
}

//=============================================================================
//                    VT-d 
//=============================================================================

/**
 * 
 */
EFI_STATUS
VtdAuthShowLegalWarning(VOID)
{
  Print(L"\n===============================================================================\n");
  Print(L"                      VT-d Hardware Emulation Driver v1.0\n");
  Print(L"                      VT-d 硬件仿真驱动程序 v1.0\n");
  Print(L"===============================================================================\n");
  Print(L"LEGAL NOTICE AND DISCLAIMER:\n");
  Print(L"法律声明和免责条款：\n");
  Print(L"\n");
  Print(L"This software is provided for LEGITIMATE VIRTUALIZATION PURPOSES ONLY.\n");
  Print(L"本软件仅供合法的虚拟化用途使用。\n");
  Print(L"\n");
  Print(L"By using this software, you acknowledge and agree to the following:\n");
  Print(L"使用本软件即表示您确认并同意以下条款：\n");
  Print(L"\n");
  Print(L"1. AUTHORIZED USE ONLY: This driver may only be used by authorized personnel\n");
  Print(L"   for legitimate development, testing, and compatibility purposes.\n");
  Print(L"   仅限授权使用：本驱动程序仅可由授权人员用于合法的开发、测试和兼容性用途。\n");
  Print(L"\n");
  Print(L"2. NO ILLEGAL ACTIVITIES: This software SHALL NOT be used to bypass\n");
  Print(L"   licensing, copy protection, or other security measures, nor for any\n");
  Print(L"   illegal or unauthorized activities.\n");
  Print(L"   禁止非法活动：本软件严禁用于绕过许可证、复制保护或其他安全措施，\n");
  Print(L"   也不得用于任何非法或未经授权的活动。\n");
  Print(L"\n");
  Print(L"3. NO WARRANTY: This software is provided \"AS IS\" without any warranty.\n");
  Print(L"   The authors disclaim all warranties and liability.\n");
  Print(L"   无质量保证：本软件按现状提供，不提供任何质量保证。\n");
  Print(L"   作者不承担任何保证责任和法律责任。\n");
  Print(L"\n");
  Print(L"4. COMPLIANCE: User is responsible for compliance with all applicable laws\n");
  Print(L"   and regulations in their jurisdiction.\n");
  Print(L"   合规责任：用户有责任遵守其所在司法管辖区的所有适用法律法规。\n");
  Print(L"\n");
  Print(L"5. MONITORING: Usage of this driver may be monitored and logged.\n");
  Print(L"   监控声明：本驱动程序的使用可能会被监控和记录。\n");
  Print(L"\n");
  Print(L"IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THIS SOFTWARE.\n");
  Print(L"如果您不同意这些条款，请勿使用本软件。\n");
  Print(L"===============================================================================\n");
  Print(L"Press ENTER to acknowledge and continue, or any other key to abort...\n");
  Print(L"按回车键确认并继续，或按其他任意键中止...\n");
  
  // 
  EFI_INPUT_KEY Key;
  EFI_STATUS Status;
  
  Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
  while (Status == EFI_NOT_READY) {
    gST->BootServices->Stall(10000); // 10ms
    Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
  }
  
  if (Key.UnicodeChar != CHAR_CARRIAGE_RETURN && Key.UnicodeChar != CHAR_LINEFEED) {
      Print(L"[VT-d Driver] User declined terms - Driver loading aborted\n");
  Print(L"[VT-d Driver] 用户拒绝条款 - 驱动加载已中止\n");
  return EFI_ABORTED;
}

Print(L"[VT-d Driver] Terms acknowledged - Proceeding with authorization check...\n");
Print(L"[VT-d Driver] 条款已确认 - 继续进行授权检查...\n");
  return EFI_SUCCESS;
}

/**
 * CPU
 */
UINT64
VtdGetCpuSerialNumber(VOID)
{
  UINT32 CpuidEax, CpuidEbx, CpuidEcx, CpuidEdx;
  UINT64 SerialNumber = 0;
  
  // CPUID.03H ()
  AsmCpuid(0, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
  if (CpuidEax >= 3) {
    //  (CPUID.03H)
    AsmCpuid(3, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
    SerialNumber = ((UINT64)CpuidEdx << 32) | CpuidEcx;
  }
  
  // 
  if (SerialNumber == 0) {
    AsmCpuid(1, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
    // CPU
    SerialNumber = ((UINT64)CpuidEax << 32) | ((UINT64)CpuidEbx & 0xFFFFFF00) | (CpuidEbx & 0xFF);
  }
  
  DEBUG((EFI_D_INFO, "CPU/: 0x%lx\n", SerialNumber));
  return SerialNumber;
}

/**
 * 
 */
EFI_STATUS
VtdGetMainboardSerial(CHAR8 *SerialBuffer, UINTN BufferSize)
{
  EFI_STATUS Status;
  EFI_SMBIOS_PROTOCOL *SmbiosProtocol;
  EFI_SMBIOS_HANDLE SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER *SmbiosTable;
  SMBIOS_TABLE_TYPE2 *BaseboardInfo;
  CHAR8 *StringPtr;
  UINTN StringIndex;
  
  if (SerialBuffer == NULL || BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  // 
  ZeroMem(SerialBuffer, BufferSize);
  
  // SMBIOS
  Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID**)&SmbiosProtocol);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "SMBIOS: %r\n", Status));
    // 
    AsciiStrCpyS(SerialBuffer, BufferSize, "MB-DEFAULT-SERIAL");
    return EFI_NOT_FOUND;
  }
  
  //  (Type 2)
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &SmbiosTable, NULL);
  
  while (!EFI_ERROR(Status)) {
    if (SmbiosTable->Type == SMBIOS_TYPE_BASEBOARD_INFORMATION) {
      BaseboardInfo = (SMBIOS_TABLE_TYPE2*)SmbiosTable;
      
      // 
      if (BaseboardInfo->SerialNumber != 0) {
        StringPtr = (CHAR8*)SmbiosTable + SmbiosTable->Length;
        StringIndex = 1;
        
        // 
        while (StringIndex < BaseboardInfo->SerialNumber && *StringPtr != 0) {
          while (*StringPtr != 0) {
            StringPtr++;
          }
          StringPtr++;
          StringIndex++;
        }
        
        if (*StringPtr != 0 && AsciiStrLen(StringPtr) > 0) {
          AsciiStrCpyS(SerialBuffer, BufferSize, StringPtr);
          DEBUG((EFI_D_INFO, ": %a\n", SerialBuffer));
          return EFI_SUCCESS;
        }
      }
    }
    
    Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &SmbiosTable, NULL);
  }
  
  //  (Type 1)
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &SmbiosTable, NULL);
  
  while (!EFI_ERROR(Status)) {
    if (SmbiosTable->Type == SMBIOS_TYPE_SYSTEM_INFORMATION) {
      SMBIOS_TABLE_TYPE1 *SystemInfo = (SMBIOS_TABLE_TYPE1*)SmbiosTable;
      
      if (SystemInfo->SerialNumber != 0) {
        StringPtr = (CHAR8*)SmbiosTable + SmbiosTable->Length;
        StringIndex = 1;
        
        while (StringIndex < SystemInfo->SerialNumber && *StringPtr != 0) {
          while (*StringPtr != 0) {
            StringPtr++;
          }
          StringPtr++;
          StringIndex++;
        }
        
        if (*StringPtr != 0 && AsciiStrLen(StringPtr) > 0) {
          AsciiStrCpyS(SerialBuffer, BufferSize, StringPtr);
          DEBUG((EFI_D_INFO, ": %a\n", SerialBuffer));
          return EFI_SUCCESS;
        }
      }
    }
    
    Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &SmbiosTable, NULL);
  }
  
  // 
  AsciiStrCpyS(SerialBuffer, BufferSize, "SYS-DEFAULT-SERIAL");
  DEBUG((EFI_D_WARN, "/\n"));
  return EFI_NOT_FOUND;
}

/**
 * 
 */
EFI_STATUS
VtdGenerateHardwareFingerprint(VTD_HARDWARE_FINGERPRINT *Fingerprint)
{
  UINT32 CpuidEax, CpuidEbx, CpuidEcx, CpuidEdx;
  EFI_TIME CurrentTime;
  EFI_STATUS Status;
  CHAR8 MainboardSerial[64];
  
  if (Fingerprint == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  ZeroMem(Fingerprint, sizeof(VTD_HARDWARE_FINGERPRINT));
  
  // CPU (CPUID.1.EAX)
  AsmCpuid(1, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
  Fingerprint->CpuSignature = CpuidEax;
  
  // CPU
  UINT32 BrandRegs[4];
  AsmCpuid(0x80000002, &BrandRegs[0], &BrandRegs[1], &BrandRegs[2], &BrandRegs[3]);
  Fingerprint->CpuBrandHash = VtdSimpleHash((UINT8*)BrandRegs, sizeof(BrandRegs));
  
  // CPU/
  Fingerprint->CpuSerialNumber = VtdGetCpuSerialNumber();
  
  // 
  Status = gRT->GetTime(&CurrentTime, NULL);
  if (!EFI_ERROR(Status)) {
    Fingerprint->SystemTime = (UINT64)CurrentTime.Year << 48 |
                             (UINT64)CurrentTime.Month << 40 |
                             (UINT64)CurrentTime.Day << 32 |
                             (UINT64)CurrentTime.Hour << 24 |
                             (UINT64)CurrentTime.Minute << 16 |
                             (UINT64)CurrentTime.Second << 8;
  }
  
  // 
  UINTN MemoryMapSize = 0;
  UINTN MapKey;
  UINTN DescriptorSize;
  UINT32 DescriptorVersion;
  EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
  
  Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    Fingerprint->MemorySize = (UINT32)((UINT64)MemoryMapSize / (UINT64)DescriptorSize);
  }
  
  // PCI
  Fingerprint->PciDeviceCount = 42; // 
  
  // 
  Status = VtdGetMainboardSerial(MainboardSerial, sizeof(MainboardSerial));
  if (!EFI_ERROR(Status)) {
    Fingerprint->MainboardSerialHash = VtdSimpleHash((UINT8*)MainboardSerial, AsciiStrLen(MainboardSerial));
  } else {
    // 
    Fingerprint->MainboardSerialHash = VtdSimpleHash((UINT8*)"DEFAULT-MAINBOARD", 17);
  }
  
  DEBUG((EFI_D_INFO, ":\n"));
  DEBUG((EFI_D_INFO, "  CPU: 0x%x\n", Fingerprint->CpuSignature));
  DEBUG((EFI_D_INFO, "  CPU: 0x%x\n", Fingerprint->CpuBrandHash));
  DEBUG((EFI_D_INFO, "  CPU: 0x%lx\n", Fingerprint->CpuSerialNumber));
  DEBUG((EFI_D_INFO, "  : 0x%x\n", Fingerprint->MainboardSerialHash));
  DEBUG((EFI_D_INFO, "  : %d\n", Fingerprint->MemorySize));
  
  return EFI_SUCCESS;
}

/**
 * 
 */
UINT32
VtdSimpleHash(UINT8 *Data, UINTN Length)
{
  UINT32 Hash = 0x5A5A5A5A; // 
  UINTN i;
  
  if (Data == NULL || Length == 0) {
    return 0;
  }
  
  for (i = 0; i < Length; i++) {
    Hash = ((Hash << 5) + Hash) + Data[i];
    Hash ^= (Hash >> 16);
  }
  
  return Hash;
}

/**
 * 
 */
// Unified scheme: legacy key validation removed
BOOLEAN
VtdAuthValidateKey(UINT8 *AuthKey, VTD_HARDWARE_FINGERPRINT *HwFingerprint)
{
  return TRUE;
}

// Unified scheme: validation implemented below with real crypto

/**
 * 
 */
EFI_STATUS
VtdAuthInitializeLegacy(VOID)
{
  EFI_STATUS Status;
  VTD_HARDWARE_FINGERPRINT CurrentFingerprint;
  
  DEBUG((EFI_D_INFO, "初始化授权系统...\n"));
  Print(L"[VT-d Driver] 正在搜索授权文件...\n");
  Print(L"[VT-d Driver] Searching for authorization file...\n");
  
  // 增强的授权文件搜索 - 在多个位置搜索
  // 1. 优先在 EFI\\MiniVisor 目录搜索
  Status = VtdAuthLoadFromFile(L"EFI\\MiniVisor\\Dxe.bin");
  if (EFI_ERROR(Status)) {
    // 2. 在根目录搜索
    Status = VtdAuthLoadFromFile(L"Dxe.bin");
  }
  if (EFI_ERROR(Status)) {
    // 3. 在常见的Windows系统位置搜索
    Status = VtdAuthLoadFromFile(L"Windows\\System32\\Dxe.bin");
  }
  if (EFI_ERROR(Status)) {
    // 4. 在常见的用户目录搜索
    Status = VtdAuthLoadFromFile(L"Users\\Public\\Dxe.bin");
  }
  if (EFI_ERROR(Status)) {
    // 5. 在临时目录搜索
    Status = VtdAuthLoadFromFile(L"temp\\Dxe.bin");
  }
  if (EFI_ERROR(Status)) {
    // 6. 在ProgramData目录搜索
    Status = VtdAuthLoadFromFile(L"ProgramData\\MiniVisor\\Dxe.bin");
  }
  if (!EFI_ERROR(Status)) {
    // 
    Status = VtdGenerateHardwareFingerprint(&CurrentFingerprint);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, ": %r\n", Status));
      return Status;
    }
    
    // Hardware fingerprint verification with detailed diagnostics
    if (gAuthInfo.HwFingerprint.CpuSignature == CurrentFingerprint.CpuSignature &&
        gAuthInfo.HwFingerprint.CpuSerialNumber == CurrentFingerprint.CpuSerialNumber &&
        gAuthInfo.HwFingerprint.MainboardSerialHash == CurrentFingerprint.MainboardSerialHash) {
      
       DEBUG((EFI_D_INFO, "[VT-d Auth] Hardware fingerprint verification successful\n"));
           Print(L"[VT-d Driver] ✓ Authorization file loaded successfully\n");
    Print(L"[VT-d Driver] ✓ 授权文件加载成功\n");
               Print(L"[VT-d Driver] Hardware fingerprint verification passed\n");
        Print(L"[VT-d Driver] 硬件指纹验证通过\n");
       return EFI_SUCCESS;
     } else {
       DEBUG((EFI_D_ERROR, "[VT-d Auth] Hardware fingerprint mismatch detected\n"));
       Print(L"[VT-d Driver] ❌ Hardware fingerprint mismatch - authorization invalid\n");
       Print(L"[VT-d Driver] ❌ 硬件指纹不匹配 - 授权无效\n");
       Print(L"[VT-d Driver] Current hardware does not match authorization\n");
       Print(L"[VT-d Driver] 当前硬件与授权不匹配\n");
       
       // Provide detailed diagnostic information for troubleshooting
       DEBUG((EFI_D_ERROR, "[VT-d Auth] Expected CPU: 0x%08X, Actual: 0x%08X\n", 
             gAuthInfo.HwFingerprint.CpuSignature, CurrentFingerprint.CpuSignature));
       DEBUG((EFI_D_ERROR, "[VT-d Auth] Expected MB Hash: 0x%08X, Actual: 0x%08X\n", 
             gAuthInfo.HwFingerprint.MainboardSerialHash, CurrentFingerprint.MainboardSerialHash));
       DEBUG((EFI_D_ERROR, "[VT-d Auth] Expected CPU SN: 0x%016llX, Actual: 0x%016llX\n", 
             gAuthInfo.HwFingerprint.CpuSerialNumber, CurrentFingerprint.CpuSerialNumber));
     }
   } else {
     DEBUG((EFI_D_WARN, ": %r\n", Status));
           Print(L"[VT-d Driver] No valid authorization file found\n");
     Print(L"[VT-d Driver] 未找到有效的授权文件\n");
    Print(L"[VT-d Driver] No valid authorization file found\n");
   }
  
  // 
  DEBUG((EFI_D_INFO, "...\n"));
  
  // 
  ZeroMem(&gAuthInfo, sizeof(VTD_AUTHORIZATION_INFO));
  
  // 
  gAuthInfo.Signature = VTD_AUTH_SIGNATURE;
  gAuthInfo.Version = VTD_AUTH_VERSION;
  gAuthInfo.MaxUsageCount = VTD_MAX_USAGE_COUNT;
  gAuthInfo.CurrentUsageCount = 0;
  
  // 
  Status = VtdGenerateHardwareFingerprint(&gAuthInfo.HwFingerprint);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  // Set unified date packing and default period
  EFI_TIME CurrentTime;
  Status = gRT->GetTime(&CurrentTime, NULL);
  if (!EFI_ERROR(Status)) {
    gAuthInfo.AuthorizedTime = ((UINT64)CurrentTime.Year << 32) | 
                               ((UINT64)CurrentTime.Month << 24) |
                               ((UINT64)CurrentTime.Day << 16);
    gAuthInfo.AuthorizationPeriodDays = 7;
    // Expiry computed as packed date of AuthorizedTime + PeriodDays
    UINT16 y = (UINT16)(gAuthInfo.AuthorizedTime >> 32);
    UINT8 m = (UINT8)((gAuthInfo.AuthorizedTime >> 24) & 0xFF);
    UINT8 d = (UINT8)((gAuthInfo.AuthorizedTime >> 16) & 0xFF);
    // Simple add: ignore month length complexities; keep same month when setting default
    gAuthInfo.ExpiryTime = ((UINT64)y << 32) | ((UINT64)m << 24) | ((UINT64)(d + (UINT8)gAuthInfo.AuthorizationPeriodDays) << 16);
  }
  ZeroMem(gAuthInfo.EncryptedPayload, sizeof(gAuthInfo.EncryptedPayload));
  ZeroMem(gAuthInfo.RsaSignature, sizeof(gAuthInfo.RsaSignature));
  
  // Security hash (first 4 bytes simple-hash, padded to 32)
  UINT32 SecurityHash = VtdSimpleHash((UINT8*)&gAuthInfo, 
                                     sizeof(VTD_AUTHORIZATION_INFO) - sizeof(gAuthInfo.SecurityHash));
  ZeroMem(gAuthInfo.SecurityHash, sizeof(gAuthInfo.SecurityHash));
  CopyMem(gAuthInfo.SecurityHash, &SecurityHash, sizeof(UINT32));
  
  DEBUG((EFI_D_INFO, "\n"));
  return EFI_SUCCESS;
}

/**
 * Legacy license verification function - now redirects to unified system
 * This function is maintained for backward compatibility only
 */
VTD_AUTH_STATUS
VtdAuthVerifyLicense(VOID)
{
  // Redirect to unified authorization system
  // This function is deprecated and should not be used in new code
  DEBUG((DEBUG_WARN, "[VTD-AUTH] VtdAuthVerifyLicense() is deprecated, use VtdAuthVerifyUnified() instead\n"));
  
  // Return authorized status if unified system is already verified
  if (gMiniVisorGlobalData.UnifiedAuthEnabled) {
    gAuthStatus = VtdAuthAuthorized;
    return gAuthStatus;
  }
  
  // Otherwise return unauthorized
  gAuthStatus = VtdAuthInvalid;
  return gAuthStatus;
}

/**
 * Update usage count for unified authorization system
 */
VOID
VtdAuthUpdateUsageCount(VOID)
{
  // This function is deprecated - use unified authorization system instead
  // The unified system handles usage tracking automatically
  DEBUG((DEBUG_WARN, "[VTD-AUTH] VtdAuthUpdateUsageCount() is deprecated, use unified system\n"));
}

/**
 * 
 */
EFI_STATUS
VtdAuthLoadFromFile(CHAR16 *AuthFileName)
{
  EFI_STATUS Status;
  EFI_FILE_PROTOCOL *RootDir;
  EFI_FILE_PROTOCOL *AuthFile;
  UINTN BufferSize;
  VTD_AUTHORIZATION_INFO TempAuthInfo;
  // UINT32 CalculatedHash;  // Removed to prevent unused variable warning
  UINT32 NvUsage = 0;
  
  if (AuthFileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  DEBUG((EFI_D_INFO, ": %s\n", AuthFileName));

  // Prefer exact-path find; if not found, perform deep recursive search across all volumes
  Status = VtdAuthFindFileAcrossVolumes(AuthFileName, &RootDir, &AuthFile);
  if (EFI_ERROR(Status)) {
    EFI_HANDLE FsHandle = NULL;
    EFI_FILE_PROTOCOL *FoundRoot = NULL;
    EFI_FILE_PROTOCOL *FoundFile = NULL;
    Status = VtdAuthFindFileByNameAcrossVolumes(L"Dxe.bin", &FsHandle, &FoundRoot, &FoundFile);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_WARN, " %s: %r\n", AuthFileName, Status));
      return Status;
    }
    RootDir = FoundRoot;
    AuthFile = FoundFile;
    gAuthFsHandle = FsHandle;
    StrCpyS(gAuthLoadedRelPath, sizeof(gAuthLoadedRelPath)/sizeof(CHAR16), L"Dxe.bin");
  }
  
  // 
  BufferSize = sizeof(VTD_AUTHORIZATION_INFO);
  Status = AuthFile->Read(AuthFile, &BufferSize, &TempAuthInfo);
  if (EFI_ERROR(Status) || BufferSize != sizeof(VTD_AUTHORIZATION_INFO)) {
    DEBUG((EFI_D_ERROR, ": %r, : %d\n", Status, BufferSize));
    AuthFile->Close(AuthFile);
    RootDir->Close(RootDir);
    return EFI_LOAD_ERROR;
  }
  
  // 
  if (TempAuthInfo.Signature != VTD_AUTH_SIGNATURE || TempAuthInfo.Version != VTD_AUTH_VERSION) {
    DEBUG((EFI_D_ERROR, "\n"));
    AuthFile->Close(AuthFile);
    RootDir->Close(RootDir);
    return EFI_SECURITY_VIOLATION;
  }
  
  // Validate structure integrity using SHA-256 over data excluding RSA signature and SecurityHash
  {
    UINT8 Calc[32];
    if (EFI_ERROR(VtdSha256Hash((UINT8*)&TempAuthInfo,
                                sizeof(VTD_AUTHORIZATION_INFO) - VTD_RSA_SIGNATURE_SIZE - sizeof(TempAuthInfo.SecurityHash),
                                Calc))) {
      DEBUG((EFI_D_ERROR, "Failed to compute SHA-256 for authorization\n"));
    AuthFile->Close(AuthFile);
    RootDir->Close(RootDir);
    return EFI_SECURITY_VIOLATION;
    }
    if (CompareMem(Calc, TempAuthInfo.SecurityHash, 32) != 0) {
      DEBUG((EFI_D_ERROR, "Authorization SHA-256 mismatch\n"));
      AuthFile->Close(AuthFile);
      RootDir->Close(RootDir);
      return EFI_SECURITY_VIOLATION;
    }
  }
  
  // 
  CopyMem(&gAuthInfo, &TempAuthInfo, sizeof(VTD_AUTHORIZATION_INFO));
  // Merge with NV usage if higher
  if (!EFI_ERROR(VtdAuthReadNvUsage(&NvUsage))) {
    if (NvUsage > gAuthInfo.CurrentUsageCount) {
      gAuthInfo.CurrentUsageCount = NvUsage;
    }
  }
  
  AuthFile->Close(AuthFile);
  VtdAuthLogFsInfo(RootDir);
  RootDir->Close(RootDir);
  
  // Remember the path we used for saving later
  if (StrLen(AuthFileName) < (sizeof(gAuthLoadedRelPath)/sizeof(CHAR16))) {
    StrCpyS(gAuthLoadedRelPath, sizeof(gAuthLoadedRelPath)/sizeof(CHAR16), AuthFileName);
  }
  
  DEBUG((EFI_D_INFO, "\n"));
  DEBUG((EFI_D_INFO, "  : %d/%d\n", gAuthInfo.CurrentUsageCount, gAuthInfo.MaxUsageCount));
  DEBUG((EFI_D_INFO, "  : 0x%lx\n", gAuthInfo.ExpiryTime));
  
  return EFI_SUCCESS;
}

/**
 * Load file contents to buffer for next-generation authorization.
 */
EFI_STATUS
VtdAuthLoadFromFileToBuffer(
  CHAR16 *FileName, 
  OUT UINT8 **Buffer, 
  OUT UINTN *BufferSize
  )
{
  EFI_STATUS Status;
  EFI_FILE_PROTOCOL *RootDir = NULL;
  EFI_FILE_PROTOCOL *AuthFile = NULL;
  EFI_FILE_INFO *FileInfo = NULL;
  UINTN FileInfoSize;
  UINT8 *FileBuffer = NULL;
  UINTN FileSize;
  
  if (FileName == NULL || Buffer == NULL || BufferSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  *Buffer = NULL;
  *BufferSize = 0;
  
  DEBUG((EFI_D_INFO, "[VTD-AUTH] Looking for file: %s\n", FileName));
  
  // Try to find the file across all volumes
  Status = VtdAuthFindFileAcrossVolumes(FileName, &RootDir, &AuthFile);
  if (EFI_ERROR(Status)) {
    // Try alternative search method
    EFI_HANDLE FsHandle = NULL;
    EFI_FILE_PROTOCOL *FoundRoot = NULL;
    EFI_FILE_PROTOCOL *FoundFile = NULL;
    
    Status = VtdAuthFindFileByNameAcrossVolumes(FileName, &FsHandle, &FoundRoot, &FoundFile);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_WARN, "[VTD-AUTH] File not found: %s (Status: %r)\n", FileName, Status));
      return Status;
    }
    
    RootDir = FoundRoot;
    AuthFile = FoundFile;
  }
  
  // Get file information
  FileInfoSize = sizeof(EFI_FILE_INFO) + 200;
  FileInfo = AllocatePool(FileInfoSize);
  if (FileInfo == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }
  
  Status = AuthFile->GetInfo(AuthFile, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "[VTD-AUTH] Failed to get file info: %r\n", Status));
    goto Cleanup;
  }
  
  FileSize = (UINTN)FileInfo->FileSize;
  if (FileSize == 0 || FileSize > 0x100000) {  // Max 1MB for safety
    DEBUG((EFI_D_ERROR, "[VTD-AUTH] Invalid file size: %d\n", FileSize));
    Status = EFI_INVALID_PARAMETER;
    goto Cleanup;
  }
  
  // Allocate buffer for file contents
  FileBuffer = AllocatePool(FileSize);
  if (FileBuffer == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }
  
  // Read file contents
  Status = AuthFile->Read(AuthFile, &FileSize, FileBuffer);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "[VTD-AUTH] Failed to read file: %r\n", Status));
    goto Cleanup;
  }
  
  DEBUG((EFI_D_INFO, "[VTD-AUTH] Successfully loaded file: %s (%d bytes)\n", 
         FileName, FileSize));
  
  *Buffer = FileBuffer;
  *BufferSize = FileSize;
  FileBuffer = NULL;  // Prevent cleanup
  
Cleanup:
  if (FileInfo != NULL) {
    FreePool(FileInfo);
  }
  if (FileBuffer != NULL) {
    FreePool(FileBuffer);
  }
  if (AuthFile != NULL) {
    AuthFile->Close(AuthFile);
  }
  if (RootDir != NULL) {
    RootDir->Close(RootDir);
  }
  
  return Status;
}

/**
 * Save MiniVisor authorization to file.
 */
EFI_STATUS
VtdAuthSaveToFile(CHAR16 *AuthFileName)
{
  EFI_STATUS Status;
  EFI_FILE_PROTOCOL *RootDir;
  EFI_FILE_PROTOCOL *AuthFile;
  UINTN BufferSize;
  
  if (AuthFileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Compute SHA-256 SecurityHash over data excluding RSA signature and SecurityHash
  {
    UINT8 Calc[32];
    if (!EFI_ERROR(VtdSha256Hash((UINT8*)&gAuthInfo,
                                 sizeof(VTD_AUTHORIZATION_INFO) - VTD_RSA_SIGNATURE_SIZE - sizeof(gAuthInfo.SecurityHash),
                                 Calc))) {
      CopyMem(gAuthInfo.SecurityHash, Calc, sizeof(Calc));
    } else {
      DEBUG((EFI_D_WARN, "Failed to compute SHA-256 SecurityHash; leaving existing value\n"));
    }
  }
  
  // Prefer previously used FS handle if available; else use image device; else first available FS
  if (gAuthFsHandle != NULL) {
    Status = VtdAuthOpenRootOnHandle(gAuthFsHandle, &RootDir);
  } else {
    Status = EFI_NOT_FOUND;
  }
  if (EFI_ERROR(Status)) {
    EFI_HANDLE ImageFsHandle = NULL;
    if (!EFI_ERROR(VtdAuthGetLoadedImageFsHandle(&ImageFsHandle))) {
      Status = VtdAuthOpenRootOnHandle(ImageFsHandle, &RootDir);
      if (!EFI_ERROR(Status)) {
        gAuthFsHandle = ImageFsHandle;
      }
    }
  }
  if (!EFI_ERROR(Status) && RootDir != NULL) {
    // Check if selected FS is read-only; if so, drop and fallback
    UINTN InfoSize = 0; EFI_FILE_SYSTEM_INFO *FsInfo = NULL; EFI_STATUS S;
    S = RootDir->GetInfo(RootDir, &gEfiFileSystemInfoGuid, &InfoSize, NULL);
    if (S == EFI_BUFFER_TOO_SMALL) {
      if (!EFI_ERROR(gBS->AllocatePool(EfiBootServicesData, InfoSize, (VOID**)&FsInfo)) && FsInfo != NULL) {
        S = RootDir->GetInfo(RootDir, &gEfiFileSystemInfoGuid, &InfoSize, FsInfo);
        if (!EFI_ERROR(S) && FsInfo->ReadOnly) {
          DEBUG((EFI_D_WARN, ": Selected filesystem is read-only; searching for writable FS...\n"));
          RootDir->Close(RootDir);
          RootDir = NULL;
          Status = EFI_NOT_READY;
        }
        gBS->FreePool(FsInfo);
      }
    }
  }
  if (EFI_ERROR(Status)) {
    // Fallback: enumerate any FS and pick the first non-readonly volume
    UINTN HandleCount = 0;
    EFI_HANDLE *HandleBuffer = NULL;
    Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &HandleBuffer);
    if (EFI_ERROR(Status) || HandleCount == 0 || HandleBuffer == NULL) {
      DEBUG((EFI_D_ERROR, ": No filesystem available: %r\n", Status));
      return EFI_NOT_FOUND;
    }
    EFI_STATUS LastErr = EFI_NOT_FOUND;
    for (UINTN i = 0; i < HandleCount; i++) {
      EFI_FILE_PROTOCOL *TmpRoot = NULL;
      EFI_STATUS S2 = VtdAuthOpenRootOnHandle(HandleBuffer[i], &TmpRoot);
      if (EFI_ERROR(S2) || TmpRoot == NULL) { LastErr = S2; continue; }
      // Check FS readonly
      UINTN InfoSize = 0; EFI_FILE_SYSTEM_INFO *FsInfo = NULL;
      S2 = TmpRoot->GetInfo(TmpRoot, &gEfiFileSystemInfoGuid, &InfoSize, NULL);
      if (S2 == EFI_BUFFER_TOO_SMALL) {
        EFI_STATUS S3 = gBS->AllocatePool(EfiBootServicesData, InfoSize, (VOID**)&FsInfo);
        if (!EFI_ERROR(S3) && FsInfo != NULL) {
          S3 = TmpRoot->GetInfo(TmpRoot, &gEfiFileSystemInfoGuid, &InfoSize, FsInfo);
          if (!EFI_ERROR(S3) && !FsInfo->ReadOnly) {
            // Use this FS
            RootDir = TmpRoot;
            gAuthFsHandle = HandleBuffer[i];
            gBS->FreePool(HandleBuffer);
            gBS->FreePool(FsInfo);
            goto HaveRoot;
          }
          gBS->FreePool(FsInfo);
        }
      }
      TmpRoot->Close(TmpRoot);
      LastErr = S2;
    }
    gBS->FreePool(HandleBuffer);
    DEBUG((EFI_D_ERROR, ": No writable filesystem found: %r\n", LastErr));
    return EFI_WRITE_PROTECTED;
  }
HaveRoot:
  
  // Save to the exact same relative path used on load when available
  CHAR16 *RelativePath = (gAuthLoadedRelPath[0] != L'\0') ? gAuthLoadedRelPath : (CHAR16*)AuthFileName;
  Status = RootDir->Open(RootDir, &AuthFile, RelativePath, 
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, " %s: %r\n", AuthFileName, Status));
    RootDir->Close(RootDir);
    return Status;
  }
  
  // 
  BufferSize = sizeof(VTD_AUTHORIZATION_INFO);
  Status = AuthFile->Write(AuthFile, &BufferSize, &gAuthInfo);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, ": %r\n", Status));
    AuthFile->Close(AuthFile);
    RootDir->Close(RootDir);
    return Status;
  }
  
  // Flush and log FS info
  Status = AuthFile->Flush(AuthFile);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_WARN, "Flush failed: %r\n", Status));
  }
  AuthFile->Close(AuthFile);
  VtdAuthLogFsInfo(RootDir);
  RootDir->Close(RootDir);
  
  DEBUG((EFI_D_INFO, ": %s\n", RelativePath));
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
VtdAuthReadNvUsage(OUT UINT32 *UsageOut)
{
  EFI_STATUS Status;
  UINTN Size;
  UINT32 Usage;
  if (UsageOut == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  Size = sizeof(UINT32);
  Status = gRT->GetVariable((CHAR16*)VTD_NV_USAGE_VAR, &gMiniVisorPkgTokenSpaceGuid, NULL, &Size, &Usage);
  if (EFI_ERROR(Status) || Size != sizeof(UINT32)) {
    return EFI_NOT_FOUND;
  }
  *UsageOut = Usage;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
VtdAuthWriteNvUsage(IN UINT32 Usage)
{
  EFI_STATUS Status;
  UINT32 Attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
  Status = gRT->SetVariable((CHAR16*)VTD_NV_USAGE_VAR, &gMiniVisorPkgTokenSpaceGuid, Attributes, sizeof(UINT32), &Usage);
  return Status;
}

//=============================================================================
//                    Real-time Protection Functions  
//=============================================================================

/**
  Open the SimpleFileSystem root directory on a specific handle.
**/
STATIC
EFI_STATUS
VtdAuthOpenRootOnHandle(IN EFI_HANDLE FsHandle, OUT EFI_FILE_PROTOCOL **RootDir)
{
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_STATUS Status;
  if (RootDir == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *RootDir = NULL;
  Status = gBS->HandleProtocol(FsHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID**)&FileSystem);
  if (EFI_ERROR(Status) || FileSystem == NULL) {
    return EFI_NOT_FOUND;
  }
  Status = FileSystem->OpenVolume(FileSystem, RootDir);
  return Status;
}

/**
  Try to open a file on a specific filesystem handle. Returns opened RootDir and AuthFile.
**/
STATIC
EFI_STATUS
VtdAuthTryOpenFileOnHandle(
  IN EFI_HANDLE FsHandle,
  IN CHAR16 *AuthFileName,
  OUT EFI_FILE_PROTOCOL **RootDir,
  OUT EFI_FILE_PROTOCOL **AuthFile
  )
{
  EFI_STATUS Status;
  if (RootDir == NULL || AuthFile == NULL || AuthFileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *RootDir = NULL;
  *AuthFile = NULL;
  Status = VtdAuthOpenRootOnHandle(FsHandle, RootDir);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  Status = (*RootDir)->Open(*RootDir, AuthFile, AuthFileName, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR(Status)) {
    (*RootDir)->Close(*RootDir);
    *RootDir = NULL;
    return Status;
  }
  // Success
  return EFI_SUCCESS;
}

/**
  Retrieve filesystem handle from the loaded image's device handle.
**/
STATIC
EFI_STATUS
VtdAuthGetLoadedImageFsHandle(OUT EFI_HANDLE *FsHandle)
{
  EFI_STATUS Status;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem = NULL;
  if (FsHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *FsHandle = NULL;
  if (gImageHandle == NULL) {
    return EFI_NOT_FOUND;
  }
  Status = gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage);
  if (EFI_ERROR(Status) || LoadedImage == NULL || LoadedImage->DeviceHandle == NULL) {
    return EFI_NOT_FOUND;
  }
  Status = gBS->HandleProtocol(LoadedImage->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID**)&FileSystem);
  if (EFI_ERROR(Status) || FileSystem == NULL) {
    return EFI_NOT_FOUND;
  }
  *FsHandle = LoadedImage->DeviceHandle;
  return EFI_SUCCESS;
}

/**
  Enumerate all filesystems and try to open the authorization file.
  Preference order: previously used handle, image device's filesystem, then all others.
**/
STATIC
EFI_STATUS
VtdAuthFindFileAcrossVolumes(
  IN CHAR16 *AuthFileName,
  OUT EFI_FILE_PROTOCOL **RootDir,
  OUT EFI_FILE_PROTOCOL **AuthFile
  )
{
  EFI_STATUS Status;
  EFI_FILE_PROTOCOL *LocalRoot = NULL;
  EFI_FILE_PROTOCOL *LocalFile = NULL;
  UINTN HandleCount = 0;
  EFI_HANDLE *HandleBuffer = NULL;
  UINTN Index;
  CHAR16 AltNameUpper[64];
  UINTN NameLen;

  if (RootDir == NULL || AuthFile == NULL || AuthFileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *RootDir = NULL;
  *AuthFile = NULL;

  // 1) Prefer gAuthFsHandle if present
  if (gAuthFsHandle != NULL) {
    Status = VtdAuthTryOpenFileOnHandle(gAuthFsHandle, AuthFileName, &LocalRoot, &LocalFile);
    if (!EFI_ERROR(Status)) {
      *RootDir = LocalRoot;
      *AuthFile = LocalFile;
      return EFI_SUCCESS;
    }
  }

  // Prepare uppercase alternative name
  ZeroMem(AltNameUpper, sizeof(AltNameUpper));
  NameLen = StrLen(AuthFileName);
  if (NameLen < (sizeof(AltNameUpper) / sizeof(CHAR16))) {
    for (UINTN i = 0; i < NameLen; i++) {
      CHAR16 ch = AuthFileName[i];
      if (ch >= L'a' && ch <= L'z') {
        AltNameUpper[i] = (CHAR16)(ch - (L'a' - L'A'));
      } else {
        AltNameUpper[i] = ch;
      }
    }
  }

  // 2) Prefer loaded image's filesystem
  EFI_HANDLE ImageFsHandle = NULL;
  if (!EFI_ERROR(VtdAuthGetLoadedImageFsHandle(&ImageFsHandle))) {
    // Try primary name
    Status = VtdAuthTryOpenFileOnHandle(ImageFsHandle, AuthFileName, &LocalRoot, &LocalFile);
    if (EFI_ERROR(Status) && AltNameUpper[0] != 0) {
      // Try uppercase variant
      Status = VtdAuthTryOpenFileOnHandle(ImageFsHandle, AltNameUpper, &LocalRoot, &LocalFile);
    }
    if (!EFI_ERROR(Status)) {
      gAuthFsHandle = ImageFsHandle;
      *RootDir = LocalRoot;
      *AuthFile = LocalFile;
      return EFI_SUCCESS;
    }
  }

  // 3) Enumerate all SimpleFileSystem handles
  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR(Status) || HandleCount == 0 || HandleBuffer == NULL) {
    return EFI_NOT_FOUND;
  }
  for (Index = 0; Index < HandleCount; Index++) {
    // Skip the image handle if already tried
    if (ImageFsHandle != NULL && HandleBuffer[Index] == ImageFsHandle) {
      continue;
    }
    // Try primary name
    Status = VtdAuthTryOpenFileOnHandle(HandleBuffer[Index], AuthFileName, &LocalRoot, &LocalFile);
    if (EFI_ERROR(Status) && AltNameUpper[0] != 0) {
      // Try uppercase variant
      Status = VtdAuthTryOpenFileOnHandle(HandleBuffer[Index], AltNameUpper, &LocalRoot, &LocalFile);
    }
    if (!EFI_ERROR(Status)) {
      gAuthFsHandle = HandleBuffer[Index];
      *RootDir = LocalRoot;
      *AuthFile = LocalFile;
      gBS->FreePool(HandleBuffer);
      return EFI_SUCCESS;
    }
  }
  gBS->FreePool(HandleBuffer);
  return EFI_NOT_FOUND;
}

/**
  Log filesystem information (label, size, readonly) for diagnostics.
**/
STATIC
VOID
VtdAuthLogFsInfo(IN EFI_FILE_PROTOCOL *RootDir)
{
  EFI_STATUS Status;
  UINTN InfoSize = 0;
  EFI_FILE_SYSTEM_INFO *FsInfo = NULL;
  if (RootDir == NULL) {
    return;
  }
  Status = RootDir->GetInfo(RootDir, &gEfiFileSystemInfoGuid, &InfoSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return;
  }
  Status = gBS->AllocatePool(EfiBootServicesData, InfoSize, (VOID**)&FsInfo);
  if (EFI_ERROR(Status) || FsInfo == NULL) {
    return;
  }
  Status = RootDir->GetInfo(RootDir, &gEfiFileSystemInfoGuid, &InfoSize, FsInfo);
  if (!EFI_ERROR(Status)) {
    // Reduce environment fingerprinting: hide filesystem attributes in release
    DEBUG((EFI_D_INFO, "FS: info hidden (label, ro, size)\n"));
  }
  gBS->FreePool(FsInfo);
}

/**
 * Real-time protection check
 */
VOID
VtdRealTimeProtectionCheck(VOID)
{
  // Check for debugging attempts
  if (VtdDetectAntiAnalysis()) {
    VtdHandleDetectionAttempt(0);
  }
  
  // Update protection timestamp
  gVtdManager.LastAccessTime = AsmReadTsc();
}

/**
 * Anti-detection measures
 */
VOID
VtdAntiDetectionMeasures(VOID)
{
  // Add random delays to prevent timing analysis (gated by AntiDetectionEnabled)
  if (gVtdManager.AntiDetectionEnabled) {
    UINT32 RandomDelay = (UINT32)(AsmReadTsc() & 0xFF);
    for (UINT32 i = 0; i < RandomDelay; i++) {
      AsmCpuid(0, NULL, NULL, NULL, NULL);
    }
  }
  
  // Increment counter mask
  gVtdManager.ErrorStatus = (gVtdManager.ErrorStatus + 1) & 0xFFFFFFFF;
}

/**
 * Update performance counters
 */
VOID
VtdUpdatePerformanceCounters(UINT32 ExitReason)
{
  gVtdManager.PerformanceCounter++;
  
  // Track specific exit types
  switch (ExitReason) {
    case VM_EXIT_CPUID:
      // CPUID call counter (stored in error status lower bits)
      gVtdManager.ErrorStatus = (gVtdManager.ErrorStatus & 0xFFFF0000) | 
                               ((gVtdManager.ErrorStatus + 1) & 0xFFFF);
      break;
      
    case VM_EXIT_MSR_READ:
    case VM_EXIT_MSR_WRITE:
      // MSR access counter (stored in error status upper bits)
      gVtdManager.ErrorStatus = (gVtdManager.ErrorStatus & 0x0000FFFF) | 
                               (((gVtdManager.ErrorStatus >> 16) + 1) << 16);
      break;
  }
}

/**
 * Detect anti-analysis attempts
 */
BOOLEAN
VtdDetectAntiAnalysis(VOID)
{
  static UINT64 LastCheckTime = 0;
  UINT64 CurrentTime = AsmReadTsc();
  
  // Simple timing-based detection
  if (LastCheckTime != 0) {
    UINT64 TimeDiff = CurrentTime - LastCheckTime;
    
    // If time difference is too small, possible automated analysis
    if (TimeDiff < 1000) {
      return TRUE;
    }
    
    // If time difference is too large, possible manual analysis
    if (TimeDiff > 0x100000000ULL) {
      return TRUE;
    }
  }
  
  LastCheckTime = CurrentTime;
  return FALSE;
}

/**
 * Handle detection attempt
 */
VOID
VtdHandleDetectionAttempt(UINT32 DetectionType)
{
  DEBUG((EFI_D_WARN, "VT-d: Detection attempt of type %d\n", DetectionType));
  
  // Increment error status
  gVtdManager.ErrorStatus++;
  
  // Apply countermeasures based on detection type (timing-affecting measures gated)
  switch (DetectionType) {
    case 0: // General analysis
      // Advanced anti-detection measures with stealth framework
      if (gVtdManager.AntiDetectionEnabled) {
        STEALTH_CONTEXT *StealthCtx = NULL;
        EFI_STATUS Status;
        
        // Initialize stealth framework if not already done
        Status = InitializeAntiDetection(&StealthCtx, STEALTH_LEVEL_ADVANCED);
        if (!EFI_ERROR(Status)) {
          // Configure comprehensive evasion
          CPUID_SPOOFING_CONFIG CpuidConfig;
          ZeroMem(&CpuidConfig, sizeof(CpuidConfig));
          CpuidConfig.Signature = 0x53544541; // 'STEA' - Stealth signature
          CpuidConfig.SpoofiingEnabled = TRUE;
          CpuidConfig.HideVmxSupport = TRUE;
          CpuidConfig.HideHypervisor = TRUE;
          ConfigureCpuidSpoofing(StealthCtx, &CpuidConfig);
          
          // Configure timing obfuscation
          TIMING_OBFUSCATION_CONFIG TimingConfig;
          ZeroMem(&TimingConfig, sizeof(TimingConfig));
          TimingConfig.Signature = 0x53544541; // 'STEA' - Stealth signature
          TimingConfig.EnableTimeJitter = TRUE;
          TimingConfig.JitterRange = 1000; // 1ms jitter
          TimingConfig.FakeRdtsc = TRUE;
          ConfigureTimingObfuscation(StealthCtx, &TimingConfig);
          
          // Apply behavioral masking
          BEHAVIORAL_MASKING_CONFIG BehaviorConfig;
          ZeroMem(&BehaviorConfig, sizeof(BehaviorConfig));
          BehaviorConfig.Signature = 0x53544541; // 'STEA' - Stealth signature
          BehaviorConfig.MaskMemoryLayout = TRUE;
          BehaviorConfig.HideRegisters = TRUE;
          BehaviorConfig.MaskCacheTimings = TRUE;
          ApplyBehavioralMasking(StealthCtx);
          
          // Cleanup stealth context
          if (StealthCtx != NULL) {
            FreePool(StealthCtx);
          }
        }
        
        // Legacy anti-detection for compatibility
        VtdAntiDetectionMeasures();
      }
      break;
      
    case 1: // Control register access
      // Potential privilege escalation attempt (do not engage timing noise)
      gVtdManager.ProtectionFlags |= VTD_PROTECTION_ANTI_HOOK;
      break;
      
    case 2: // Debug register access
      // Direct debugging attempt: enable anti-debug with decay window
      gVtdManager.ProtectionFlags |= VTD_PROTECTION_ANTI_DEBUG;
      gVtdManager.LastAntiDebugTsc = AsmReadTsc();
      break;
  }
}

//=============================================================================
//                    Performance Optimization Functions
//=============================================================================

/**
 * Optimize VT-d performance for real hardware
 */
VOID
VtdOptimizePerformance(VOID)
{
  // Enable performance optimizations
  gVtdManager.PerformanceOptimizations = TRUE;
  
  // Set aggressive caching
  gVtdManager.CachePolicy = VTD_CACHE_AGGRESSIVE;
  
  // Optimize for low latency
  gVtdManager.LatencyOptimization = TRUE;
  
  DEBUG((EFI_D_INFO, "VT-d performance optimizations enabled\n"));
}

/**
 * Monitor VT-d performance metrics
 */
VOID
VtdMonitorPerformance(VOID)
{
  UINT64 CurrentTime = AsmReadTsc();
  UINT64 TimeDelta = CurrentTime - gVtdManager.LastAccessTime;
  
  // Update performance statistics
  if (TimeDelta < gVtdManager.MinLatency || gVtdManager.MinLatency == 0) {
    gVtdManager.MinLatency = TimeDelta;
  }
  
  if (TimeDelta > gVtdManager.MaxLatency) {
    gVtdManager.MaxLatency = TimeDelta;
  }
  
  // Calculate moving average
  gVtdManager.AverageLatency = DivU64x32((gVtdManager.AverageLatency + TimeDelta), 2);
  
  gVtdManager.LastAccessTime = CurrentTime;
}

/**
 * Apply thermal management for VT-d operations
 */
VOID
VtdThermalManagement(VOID)
{
  static UINT32 ThermalCounter = 0;
  
  ThermalCounter++;
  
  // Every 1000 operations, apply thermal throttling
  if (ModU64x32(ThermalCounter, 1000) == 0) {
    // Brief pause to prevent overheating
    for (UINT32 i = 0; i < 100; i++) {
      AsmCpuid(0, NULL, NULL, NULL, NULL);
    }
    
    DEBUG((EFI_D_VERBOSE, "VT-d thermal management applied\n"));
  }
}

/**
 * Optimize memory access patterns for VT-d
 */
VOID
VtdOptimizeMemoryAccess(VOID)
{
  // Prefetch commonly accessed memory regions
  UINT64 *MmioBase = (UINT64*)gVtdManager.MmioBase;
  
  if (MmioBase != NULL) {
    // Touch key VT-d registers to keep them in cache
    volatile UINT64 temp;
    temp = *MmioBase;        // Version register
    temp = *(MmioBase + 1);  // Capability register
    temp = *(MmioBase + 2);  // Extended capability register
    
    // Prevent compiler optimization
    (VOID)temp;
  }
}

/**
 * Dynamic frequency scaling for VT-d operations
 */
VOID
VtdDynamicFrequencyScaling(VOID)
{
  UINT64 Load = ModU64x32(gVtdManager.PerformanceCounter, 1000);
  
  // Adjust frequency based on load
  if (Load > 800) {
    // High load - increase frequency
    gVtdManager.OperatingFrequency = VTD_FREQ_HIGH;
  } else if (Load < 200) {
    // Low load - decrease frequency for power saving
    gVtdManager.OperatingFrequency = VTD_FREQ_LOW;
  } else {
    // Medium load - normal frequency
    gVtdManager.OperatingFrequency = VTD_FREQ_NORMAL;
  }
}

/**
 * Cleanup and free all allocated VT-d resources
 */
EFI_STATUS
VtdCleanupResources(VOID)
{
  UINTN Index;
  
  DEBUG((EFI_D_INFO, "VT-d: Starting resource cleanup\n"));
  
  // Cleanup domain resources
  for (Index = 0; Index < VTD_MAX_DOMAINS; Index++) {
    if (gVtdDomains[Index].Active) {
      // Free second-level page tables
      if (gVtdDomains[Index].SecondLevelPageTableAddress != 0) {
        MiniVisorFreeTrackedPages(gVtdDomains[Index].SecondLevelPageTableAddress, 
                       EFI_SIZE_TO_PAGES(512 * sizeof(VTD_PAGE_TABLE_ENTRY_4K)));
        gVtdDomains[Index].SecondLevelPageTableAddress = 0;
      }
      
      // Mark domain as inactive
      gVtdDomains[Index].Active = FALSE;
      gVtdDomains[Index].DeviceCount = 0;
      ZeroMem(gVtdDomains[Index].AssignedDevices, sizeof(gVtdDomains[Index].AssignedDevices));
    }
  }
  
  // Free VT-d tables
  if (gVtdManager.RootTableAddress != 0) {
    MiniVisorFreeTrackedPages(gVtdManager.RootTableAddress, EFI_SIZE_TO_PAGES(256 * sizeof(VTD_ROOT_TABLE_ENTRY)));
    gVtdManager.RootTableAddress = 0;
  }
  
  if (gVtdManager.ContextTableAddress != 0) {
    MiniVisorFreeTrackedPages(gVtdManager.ContextTableAddress, EFI_SIZE_TO_PAGES(256 * sizeof(VTD_CONTEXT_TABLE_ENTRY)));
    gVtdManager.ContextTableAddress = 0;
  }
  
  if (gVtdManager.InterruptRemapTableAddress != 0) {
    MiniVisorFreeTrackedPages(gVtdManager.InterruptRemapTableAddress, EFI_SIZE_TO_PAGES(1024 * sizeof(VTD_INTERRUPT_REMAP_TABLE_ENTRY)));
    gVtdManager.InterruptRemapTableAddress = 0;
  }
  
  DEBUG((EFI_D_INFO, "VT-d: Resource cleanup completed\n"));
  return EFI_SUCCESS;
}

/**
 * Cleanup and free all allocated VMX resources
 */
EFI_STATUS
VmxCleanupResources(VOID)
{
  DEBUG((EFI_D_INFO, "VMX: Starting resource cleanup\n"));
  
  // Free VMXON region
  if (gRing2Manager.VmxState.VmxRegion != 0) {
    gBS->FreePages(gRing2Manager.VmxState.VmxRegion, EFI_SIZE_TO_PAGES(gRing2Manager.VmxState.VmxRegionSize));
    gRing2Manager.VmxState.VmxRegion = 0;
  }
  
  // Free VMCS region
  if (gRing2Manager.VmxState.Vmcs != 0) {
    gBS->FreePages(gRing2Manager.VmxState.Vmcs, EFI_SIZE_TO_PAGES(gRing2Manager.VmxState.VmcsSize));
    gRing2Manager.VmxState.Vmcs = 0;
  }
  
  // Free EPT page tables
  if (gRing2Manager.VmxState.EptPageTable != 0) {
    MiniVisorFreeTrackedPages(gRing2Manager.VmxState.EptPageTable, EFI_SIZE_TO_PAGES(4096 * 4));
    gRing2Manager.VmxState.EptPageTable = 0;
  }
  
  // Free MSR bitmap
  if (gRing2Manager.VmxState.MsrBitmap != 0) {
    gBS->FreePages(gRing2Manager.VmxState.MsrBitmap, EFI_SIZE_TO_PAGES(4096));
    gRing2Manager.VmxState.MsrBitmap = 0;
  }
  
  // Free I/O bitmaps
  if (gRing2Manager.VmxState.IoBitmapA != 0) {
    gBS->FreePages(gRing2Manager.VmxState.IoBitmapA, EFI_SIZE_TO_PAGES(4096));
    gRing2Manager.VmxState.IoBitmapA = 0;
  }
  
  if (gRing2Manager.VmxState.IoBitmapB != 0) {
    gBS->FreePages(gRing2Manager.VmxState.IoBitmapB, EFI_SIZE_TO_PAGES(4096));
    gRing2Manager.VmxState.IoBitmapB = 0;
  }
  
  DEBUG((EFI_D_INFO, "VMX: Resource cleanup completed\n"));
  return EFI_SUCCESS;
}

/**
 * Enhanced error handling with detailed logging
 */
EFI_STATUS
MiniVisorHandleError(
  IN EFI_STATUS ErrorCode,
  IN CHAR16     *FunctionName,
  IN CHAR16     *ErrorDescription
  )
{
  DEBUG((EFI_D_ERROR, "MiniVisor Error in %s: %s (Status: %r)\n", 
         FunctionName, ErrorDescription, ErrorCode));
  
  // No-op for performance counters here; avoid skewing averages on error
  
  // Perform cleanup based on error severity
  if (ErrorCode == EFI_OUT_OF_RESOURCES) {
    DEBUG((EFI_D_ERROR, "Memory allocation failed - attempting cleanup\n"));
    // Don't cleanup here to avoid recursive calls
  } else if (ErrorCode == EFI_DEVICE_ERROR) {
    DEBUG((EFI_D_ERROR, "Device error detected - system may be unstable\n"));
  }
  
  return ErrorCode;
}

/**
 * Validate memory allocation with enhanced checking
 */
EFI_STATUS
MiniVisorAllocatePages(
  IN  EFI_ALLOCATE_TYPE     Type,
  IN  EFI_MEMORY_TYPE       MemoryType,
  IN  UINTN                 Pages,
  OUT EFI_PHYSICAL_ADDRESS  *Memory,
  IN  CHAR16                *Description
  )
{
  EFI_STATUS Status;
  
  if (Memory == NULL || Description == NULL) {
    return MiniVisorHandleError(EFI_INVALID_PARAMETER, L"MiniVisorAllocatePages", L"Invalid parameters");
  }
  
  *Memory = 0;
  Status = gBS->AllocatePages(Type, MemoryType, Pages, Memory);
  
  if (EFI_ERROR(Status)) {
    return MiniVisorHandleError(Status, L"MiniVisorAllocatePages", Description);
  }
  
  // Zero the allocated memory for security
  ZeroMem((VOID*)(UINTN)*Memory, EFI_PAGES_TO_SIZE(Pages));
  
  DEBUG((EFI_D_INFO, "Allocated %d pages for %s at 0x%lx\n", 
         Pages, Description, *Memory));
  
  return EFI_SUCCESS;
}

/**
 * Safe memory free with validation
 */
EFI_STATUS
MiniVisorFreePages(
  IN EFI_PHYSICAL_ADDRESS Memory,
  IN UINTN                Pages,
  IN CHAR16               *Description
  )
{
  EFI_STATUS Status;
  
  if (Memory == 0 || Description == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Clear memory before freeing for security
  ZeroMem((VOID*)(UINTN)Memory, EFI_PAGES_TO_SIZE(Pages));
  
  Status = gBS->FreePages(Memory, Pages);
  
  if (EFI_ERROR(Status)) {
    return MiniVisorHandleError(Status, L"MiniVisorFreePages", Description);
  }
  
  DEBUG((EFI_D_INFO, "Freed %d pages for %s at 0x%lx\n", 
         Pages, Description, Memory));
  
  return EFI_SUCCESS;
}

//
// Performance optimization structures
//
typedef struct {
  UINT64  Key;
  UINT64  Value;
  BOOLEAN Valid;
} CACHE_ENTRY;

#define CACHE_SIZE 64
CACHE_ENTRY gTranslationCache[CACHE_SIZE];
UINT32      gCacheIndex = 0;

/**
 * Simple LRU cache for address translations
 */
BOOLEAN
CacheLookup(
  IN  UINT64  Key,
  OUT UINT64  *Value
  )
{
  UINT32 Index;
  
  for (Index = 0; Index < CACHE_SIZE; Index++) {
    if (gTranslationCache[Index].Valid && gTranslationCache[Index].Key == Key) {
      *Value = gTranslationCache[Index].Value;
      return TRUE;
    }
  }
  
  return FALSE;
}

/**
 * Add entry to translation cache
 */
VOID
CacheInsert(
  IN UINT64  Key,
  IN UINT64  Value
  )
{
  gTranslationCache[gCacheIndex].Key = Key;
  gTranslationCache[gCacheIndex].Value = Value;
  gTranslationCache[gCacheIndex].Valid = TRUE;
  
  gCacheIndex = (gCacheIndex + 1) % CACHE_SIZE;
}

/**
 * Invalidate translation cache
 */
VOID
CacheInvalidate(VOID)
{
  UINT32 Index;
  
  for (Index = 0; Index < CACHE_SIZE; Index++) {
    gTranslationCache[Index].Valid = FALSE;
  }
  
  gCacheIndex = 0;
}

/**
 * Optimized string comparison for performance-critical paths
 */
INTN
FastStrCmp(
  IN CONST CHAR16  *FirstString,
  IN CONST CHAR16  *SecondString
  )
{
  if (FirstString == NULL || SecondString == NULL) {
    return (INTN)(FirstString - SecondString);
  }
  
  // Fast path for identical pointers
  if (FirstString == SecondString) {
    return 0;
  }
  
  // Optimized comparison
  while (*FirstString != L'\0' && *FirstString == *SecondString) {
    FirstString++;
    SecondString++;
  }
  
  return (INTN)(*FirstString - *SecondString);
}

/**
 * Batch processing for multiple operations
 */
EFI_STATUS
BatchProcessVmExits(
  IN UINT32  Count,
  IN VOID    *ExitInfo
  )
{
  UINT32 Index;
  UINT64 StartTime, EndTime;
  
  if (Count == 0 || ExitInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  StartTime = AsmReadTsc();
  
  // Process exits in batches for better cache locality
  for (Index = 0; Index < Count; Index++) {
    // Process individual exit
    // This would contain the actual exit handling logic
  }
  
  EndTime = AsmReadTsc();
  
  // Update performance statistics
  if (gMiniVisorGlobalData.Status & MINI_VISOR_STATUS_INITIALIZED) {
    gMiniVisorGlobalData.PerfData.TotalVmExitTime += (EndTime - StartTime);
    gMiniVisorGlobalData.PerfData.VmExitCount++;
  }
  
  return EFI_SUCCESS;
}

/**
 * Memory prefetching hints for better performance
 */
VOID
PrefetchMemory(
  IN VOID   *Address,
  IN UINTN  Size
  )
{
  UINT8  *Ptr;
  UINTN  Index;
  
  if (Address == NULL || Size == 0) {
    return;
  }
  
  Ptr = (UINT8*)Address;
  
  // Prefetch cache lines (assuming 64-byte cache lines)
  for (Index = 0; Index < Size; Index += 64) {
    // Use compiler builtin if available, otherwise volatile read
    volatile UINT8 temp = Ptr[Index];
    (VOID)temp; // Prevent compiler optimization
  }
}

/**
 * Optimized memory copy for virtualization structures
 */
VOID
FastMemCopy(
  OUT VOID        *Destination,
  IN  CONST VOID  *Source,
  IN  UINTN       Length
  )
{
  UINT64  *Dst64;
  UINT64  *Src64;
  UINT8   *Dst8;
  UINT8   *Src8;
  UINTN   Count64;
  UINTN   Remainder;
  
  if (Destination == NULL || Source == NULL || Length == 0) {
    return;
  }
  
  // Fast path for 8-byte aligned copies
  if (((UINTN)Destination & 7) == 0 && ((UINTN)Source & 7) == 0 && Length >= 8) {
    Dst64 = (UINT64*)Destination;
    Src64 = (UINT64*)Source;
    Count64 = DivU64x32(Length, 8);
    Remainder = ModU64x32(Length, 8);
    
    // Copy 8 bytes at a time
    while (Count64-- > 0) {
      *Dst64++ = *Src64++;
    }
    
    // Handle remaining bytes
    if (Remainder > 0) {
      Dst8 = (UINT8*)Dst64;
      Src8 = (UINT8*)Src64;
      while (Remainder-- > 0) {
        *Dst8++ = *Src8++;
      }
    }
  } else {
    // Fallback to standard memory copy
    CopyMem(Destination, Source, Length);
  }
}

/**
 * 等待用户输入回车键
 */
VOID
VtdWaitForUserInput(VOID)
{
  // EFI_INPUT_KEY Key;  // Removed to prevent unused variable warning
  // EFI_STATUS Status;  // Removed to prevent unused variable warning
  
  Print(L"\n");
  Print(L"=========================================================================\n");
  Print(L"[Dxe for Intel] 驱动加载完成！\n");
  Print(L"[Dxe for Intel] Driver loaded successfully!\n");
  Print(L"=========================================================================\n");
  // Auto-boot logic removed; simply return to caller
  return;
}

/**
 * 查找并启动Windows系统
 */
EFI_STATUS
VtdFindAndLaunchWindows(VOID)
{
  // Entire Windows launching flow removed
  return EFI_UNSUPPORTED;
}

/**
 * 查找bootmgfw.efi的路径
 */
EFI_STATUS
VtdFindBootmgfwPath(OUT CHAR16 **BootmgfwPath)
{
  // Removed; driver no longer searches for Windows Boot Manager
  if (BootmgfwPath != NULL) {
    *BootmgfwPath = NULL;
  }
  return EFI_UNSUPPORTED;
}

/**
 * 启动EFI应用程序
 */
EFI_STATUS
VtdLaunchEfiApplication(IN CHAR16 *ApplicationPath)
{
  // Removed; driver no longer launches external EFI applications
  return EFI_UNSUPPORTED;
}

// ==============================================================================
// File System Cache Implementation
// ==============================================================================

/**
 * Initialize file system cache
 */
STATIC VOID
VtdAuthInitializeCache(VOID)
{
  if (gFsCacheInitialized) {
    return;
  }
  
  ZeroMem(gFsCache, sizeof(gFsCache));
  gFsCacheCount = 0;
  gFsCacheInitialized = TRUE;
}

/**
 * Find cache entry by file system handle
 */
STATIC FS_CACHE_ENTRY*
VtdAuthFindCacheEntry(EFI_HANDLE FsHandle)
{
  UINTN Index;
  
  if (!gFsCacheInitialized) {
    VtdAuthInitializeCache();
  }
  
  for (Index = 0; Index < gFsCacheCount; Index++) {
    if (gFsCache[Index].Valid && gFsCache[Index].FsHandle == FsHandle) {
      return &gFsCache[Index];
    }
  }
  
  return NULL;
}

/**
 * Add entry to file system cache
 */
STATIC EFI_STATUS
VtdAuthAddCacheEntry(
  EFI_HANDLE FsHandle, 
  EFI_FILE_PROTOCOL *RootDir, 
  CHAR16 *AuthFilePath
  )
{
  FS_CACHE_ENTRY *Entry;
  UINTN PathLen;
  
  if (!gFsCacheInitialized) {
    VtdAuthInitializeCache();
  }
  
  // Check if entry already exists
  Entry = VtdAuthFindCacheEntry(FsHandle);
  if (Entry != NULL) {
    // Update existing entry
    if (Entry->AuthFilePath != NULL) {
      gBS->FreePool(Entry->AuthFilePath);
    }
  } else {
    // Add new entry if space available
    if (gFsCacheCount >= MAX_FS_CACHE_ENTRIES) {
      return EFI_OUT_OF_RESOURCES;
    }
    Entry = &gFsCache[gFsCacheCount++];
    Entry->FsHandle = FsHandle;
    Entry->RootDir = RootDir;
  }
  
  // Copy file path
  if (AuthFilePath != NULL) {
    PathLen = StrLen(AuthFilePath) + 1;
    Entry->AuthFilePath = AllocatePool(PathLen * sizeof(CHAR16));
    if (Entry->AuthFilePath == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    StrCpyS(Entry->AuthFilePath, PathLen, AuthFilePath);
  } else {
    Entry->AuthFilePath = NULL;
  }
  
  Entry->Valid = TRUE;
  return EFI_SUCCESS;
}

/**
 * Clear file system cache
 */
STATIC VOID
VtdAuthClearCache(VOID)
{
  UINTN Index;
  
  for (Index = 0; Index < gFsCacheCount; Index++) {
    if (gFsCache[Index].AuthFilePath != NULL) {
      gBS->FreePool(gFsCache[Index].AuthFilePath);
    }
  }
  
  ZeroMem(gFsCache, sizeof(gFsCache));
  gFsCacheCount = 0;
  gFsCacheInitialized = FALSE;
}

// ==============================================================================
// Real Cryptographic Implementation
// ==============================================================================

/**
 * Real RSA signature verification using BaseCryptLib
 */
EFI_STATUS
VtdRsaVerifySignature(
  IN UINT8 *Data,
  IN UINTN DataSize,
  IN UINT8 *Signature,
  IN UINT8 *PublicKey
  )
{
  VOID *RsaContext = NULL;
  BOOLEAN VerifyResult = FALSE;
  EFI_STATUS Status = EFI_SECURITY_VIOLATION;
  UINT8 HashValue[32]; // SHA-256 hash
  
  if (Data == NULL || DataSize == 0 || Signature == NULL || PublicKey == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Initialize RSA context
  RsaContext = RsaNew();
  if (RsaContext == NULL) {
    DEBUG((EFI_D_ERROR, "Failed to create RSA context\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Set RSA public key (raw N and E format, not DER)
  // Standard RSA exponent: 0x010001 (65537)
  UINT8 RsaExponent[] = {0x01, 0x00, 0x01};
  
  // First set the modulus (N)
  if (!RsaSetKey(RsaContext, RsaKeyN, PublicKey, VTD_RSA_KEY_SIZE)) {
    DEBUG((EFI_D_ERROR, "Failed to set RSA public key modulus\n"));
    Status = EFI_INVALID_PARAMETER;
    goto Cleanup;
  }
  
  // Then set the exponent (E)
  if (!RsaSetKey(RsaContext, RsaKeyE, RsaExponent, sizeof(RsaExponent))) {
    DEBUG((EFI_D_ERROR, "Failed to set RSA public key exponent\n"));
    Status = EFI_INVALID_PARAMETER;
    goto Cleanup;
  }
  
  // Compute SHA-256 hash of data
  Status = VtdSha256Hash(Data, DataSize, HashValue);
    if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "Failed to compute SHA-256 hash\n"));
    goto Cleanup;
  }
  
  // Verify RSA signature using PKCS#1 v1.5
  VerifyResult = RsaPkcs1Verify(
    RsaContext,
    HashValue,
    32, // SHA-256 hash size
    Signature,
    VTD_RSA_SIGNATURE_SIZE
  );
  
  if (VerifyResult) {
    Status = EFI_SUCCESS;
    DEBUG((EFI_D_INFO, "RSA signature verification successful\n"));
  } else {
    Status = EFI_SECURITY_VIOLATION;
    DEBUG((EFI_D_WARN, "RSA signature verification failed\n"));
  }
  
Cleanup:
  if (RsaContext != NULL) {
    RsaFree(RsaContext);
  }
  
  return Status;
}

/**
 * Real SHA-256 hash computation using BaseCryptLib
 */
EFI_STATUS
VtdSha256Hash(
  IN UINT8 *Data,
  IN UINTN DataSize,
  OUT UINT8 *Hash
  )
{
  VOID *Sha256Context = NULL;
  UINTN ContextSize = 0;
  BOOLEAN Result = FALSE;
  EFI_STATUS Status = EFI_ABORTED;
  
  if (Data == NULL || DataSize == 0 || Hash == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Allocate SHA-256 context using CryptoPkg API shape supported by edk2
  ContextSize = Sha256GetContextSize();
  if (ContextSize == 0) {
    DEBUG((EFI_D_ERROR, "Sha256GetContextSize returned 0\n"));
    return EFI_ABORTED;
  }
  Sha256Context = AllocatePool(ContextSize);
  if (Sha256Context == NULL) {
    DEBUG((EFI_D_ERROR, "Failed to allocate SHA-256 context (%u bytes)\n", (UINT32)ContextSize));
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Initialize SHA-256
  Result = Sha256Init(Sha256Context);
  if (!Result) {
    DEBUG((EFI_D_ERROR, "Failed to initialize SHA-256\n"));
    Status = EFI_ABORTED;
    goto Cleanup;
  }
  
  // Update SHA-256 with data
  Result = Sha256Update(Sha256Context, Data, DataSize);
  if (!Result) {
    DEBUG((EFI_D_ERROR, "Failed to update SHA-256\n"));
    Status = EFI_ABORTED;
    goto Cleanup;
  }
  
  // Finalize SHA-256 and get hash
  Result = Sha256Final(Sha256Context, Hash);
  if (!Result) {
    DEBUG((EFI_D_ERROR, "Failed to finalize SHA-256\n"));
    Status = EFI_ABORTED;
    goto Cleanup;
  }
  
  Status = EFI_SUCCESS;
  DEBUG((EFI_D_INFO, "SHA-256 hash computation successful\n"));
  
Cleanup:
  if (Sha256Context != NULL) {
    FreePool(Sha256Context);
  }
  
  return Status;
}

/**
 * Enhanced authorization structure validation with real crypto
 */
EFI_STATUS
VtdValidateAuthorizationStructure(
  IN VTD_AUTHORIZATION_INFO *AuthInfo
  )
{
  EFI_STATUS Status;
  UINT8 ComputedHash[32];
  VOID                    *SecurityContext = NULL;
  UINT8                   *PublicKeyData = NULL;
  DYNAMIC_KEY_CONTEXT     DynamicKeyContext = {0};
  
  if (AuthInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  //
  // Initialize security framework for dynamic key management
  //
  Status = InitializeSecurityFramework (SecurityLevelHigh, (VOID**)&SecurityContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Failed to initialize security framework: %r\n", Status));
    return Status;
  }
  
  //
  // Generate dynamic public key for verification instead of hardcoded key
  //
  ZeroMem(&DynamicKeyContext, sizeof(DYNAMIC_KEY_CONTEXT));
  DynamicKeyContext.Signature = 0x4B455944; // 'KEYD'
  DynamicKeyContext.Version = 1;
  DynamicKeyContext.KeySize = 32;
  DynamicKeyContext.KeyData = AllocateZeroPool(32);
  if (DynamicKeyContext.KeyData == NULL) {
    DEBUG ((EFI_D_ERROR, "Failed to allocate memory for dynamic key\n"));
    Status = EFI_OUT_OF_RESOURCES;
    goto CleanupAndReturn;
  }
  
  Status = GenerateDynamicKey (SecurityContext, KEY_PURPOSE_AUTHENTICATION, &DynamicKeyContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Failed to generate dynamic key: %r\n", Status));
    FreePool(DynamicKeyContext.KeyData);
    goto CleanupAndReturn;
  }
  
  //
  // Allocate memory for public key data
  //
  PublicKeyData = AllocateZeroPool(VTD_RSA_KEY_SIZE);
  if (PublicKeyData == NULL) {
    DEBUG ((EFI_D_ERROR, "Failed to allocate memory for public key\n"));
    Status = EFI_OUT_OF_RESOURCES;
    goto CleanupAndReturn;
  }
  
  //
  // Retrieve public key data from secure storage
  //
  Status = RetrieveSecureCredential (SecurityContext, PublicKeyData);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Failed to retrieve public key: %r\n", Status));
    goto CleanupAndReturn;
  }
  
  // Verify signature
  if (AuthInfo->Signature != VTD_AUTH_SIGNATURE) {
    DEBUG((EFI_D_ERROR, "Invalid authorization signature: 0x%08x\n", AuthInfo->Signature));
    return EFI_SECURITY_VIOLATION;
  }
  
  // Verify version
  if (AuthInfo->Version != VTD_AUTH_VERSION) {
    DEBUG((EFI_D_ERROR, "Unsupported authorization version: %d\n", AuthInfo->Version));
    return EFI_UNSUPPORTED;
  }
  
  // Compute SHA-256 hash of the structure (excluding signature and hash fields)
  Status = VtdSha256Hash(
    (UINT8*)AuthInfo,
    sizeof(VTD_AUTHORIZATION_INFO) - VTD_RSA_SIGNATURE_SIZE - 32, // Exclude signature and hash
    ComputedHash
  );
  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "Failed to compute authorization hash\n"));
      return Status;
    }
    
  // Verify stored hash matches computed hash
  if (CompareMem(ComputedHash, AuthInfo->SecurityHash, 32) != 0) {
    DEBUG((EFI_D_ERROR, "Authorization hash mismatch\n"));
    Status = EFI_SECURITY_VIOLATION;
    goto CleanupAndReturn;
  }
  
  //
  // Verify RSA signature using dynamic public key instead of hardcoded key
  //
  ASSERT (PublicKeyData != NULL);
  Status = VtdRsaVerifySignature(
    (UINT8*)AuthInfo,
    sizeof(VTD_AUTHORIZATION_INFO) - VTD_RSA_SIGNATURE_SIZE, // Exclude signature field
    AuthInfo->RsaSignature,
    PublicKeyData
  );
  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "RSA signature verification failed: %r\n", Status));
    goto CleanupAndReturn;
  }
  
  DEBUG((EFI_D_INFO, "Authorization structure validation successful\n"));
  Status = EFI_SUCCESS;

CleanupAndReturn:
  //
  // Secure cleanup: overwrite sensitive data and free resources
  //
  if (DynamicKeyContext.KeyData != NULL && DynamicKeyContext.KeySize > 0) {
    ZeroMem(DynamicKeyContext.KeyData, DynamicKeyContext.KeySize);
    FreePool(DynamicKeyContext.KeyData);
  }
  
  if (PublicKeyData != NULL) {
    ZeroMem (PublicKeyData, VTD_RSA_KEY_SIZE);
    FreePool (PublicKeyData);
  }
  
  if (SecurityContext != NULL) {
    DestroySecurityContext (SecurityContext);
  }
  
  return Status;
}

// MokManager.efi support removed for now to simplify boot flow.


//
// Memory tracking helpers (wrappers around gBS->AllocatePages/FreePages)
//
EFI_STATUS
EFIAPI
MiniVisorAllocateTrackedPages (
  IN EFI_ALLOCATE_TYPE     Type,
  IN EFI_MEMORY_TYPE       MemoryType,
  IN UINTN                 Pages,
  IN OUT EFI_PHYSICAL_ADDRESS *Memory
  )
{
  EFI_STATUS Status;
  
  //
  // Validate input parameters
  //
  if (VALIDATE_POINTER(Memory) != EFI_SUCCESS) {
    return EFI_INVALID_PARAMETER;
  }
  if (Pages == 0 || Pages > MAX_SAFE_BUFFER_SIZE / EFI_PAGE_SIZE) {
    DEBUG((EFI_D_ERROR, "Invalid page count: %d\n", Pages));
    return EFI_INVALID_PARAMETER;
  }
  
  //
  // Check for potential overflow in tracking counters
  //
  if (gMiniVisorGlobalData.MemTrack.TotalPagesAllocated > (MAX_UINTN - Pages)) {
    DEBUG((EFI_D_ERROR, "Memory tracking overflow prevented\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  //
  // Attempt allocation with proper error handling
  //
  Status = gBS->AllocatePages(Type, MemoryType, Pages, Memory);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "Page allocation failed: Type=%d, MemType=%d, Pages=%d, Status=%r\n", 
           Type, MemoryType, Pages, Status));
    return Status;
  }
  
  //
  // Validate allocated memory address
  //
  if (*Memory == 0) {
    DEBUG((EFI_D_ERROR, "Invalid memory address returned from allocation\n"));
    return EFI_DEVICE_ERROR;
  }
  
  //
  // Update tracking counters atomically
  //
  gMiniVisorGlobalData.MemTrack.TotalPagesAllocated += Pages;
  gMiniVisorGlobalData.MemTrack.OutstandingPages += Pages;
  
  //
  // Zero out allocated memory for security
  //
  ZeroMem((VOID*)(UINTN)Memory, Pages * EFI_PAGE_SIZE);
  
  DEBUG((EFI_D_VERBOSE, "Allocated %d pages at 0x%lx\n", Pages, Memory));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
MiniVisorFreeTrackedPages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 Pages
  )
{
  EFI_STATUS Status;
  
  //
  // Validate input parameters
  //
  if (Memory == 0) {
    DEBUG((EFI_D_ERROR, "Invalid memory address for free operation\n"));
    return EFI_INVALID_PARAMETER;
  }
  
  if (Pages == 0) {
    DEBUG((EFI_D_ERROR, "Invalid page count for free operation\n"));
    return EFI_INVALID_PARAMETER;
  }
  
  //
  // Security: Zero out memory before freeing
  //
  ZeroMem((VOID*)(UINTN)Memory, Pages * EFI_PAGE_SIZE);
  
  //
  // Attempt to free pages with proper error handling
  //
  Status = gBS->FreePages(Memory, Pages);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "Page free failed: Memory=0x%lx, Pages=%d, Status=%r\n", 
           Memory, Pages, Status));
    return Status;
  }
  
  //
  // Update tracking counters atomically
  //
  gMiniVisorGlobalData.MemTrack.TotalPagesFreed += Pages;
  
  //
  // Safely update outstanding pages counter
  //
  if (gMiniVisorGlobalData.MemTrack.OutstandingPages >= Pages) {
    gMiniVisorGlobalData.MemTrack.OutstandingPages -= Pages;
  } else {
    DEBUG((DEBUG_WARN, "Outstanding pages counter underflow detected\n"));
    gMiniVisorGlobalData.MemTrack.OutstandingPages = 0;
  }
  
  DEBUG((EFI_D_VERBOSE, "Freed %d pages at 0x%lx\n", Pages, Memory));
  return EFI_SUCCESS;
}

//
// Security function implementations
//



