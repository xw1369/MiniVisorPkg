[Defines]
  PLATFORM_NAME                  = MiniVisor
  PLATFORM_GUID                  = 87654321-4321-4321-4321-CBA987654321
  PLATFORM_VERSION               = 2.0
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/MiniVisor
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE

[LibraryClasses]
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  StackCheckLib|MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLibCrypto.inf
  IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
  RngLib|MdePkg/Library/BaseRngLib/BaseRngLib.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
  MiniVisorAuthLib|MiniVisorPkg/Library/MiniVisorAuthLib/MiniVisorAuthLib.inf
  UnifiedAuthLib|MiniVisorPkg/Library/UnifiedAuthLib/UnifiedAuthLib.inf
  MiniVisorAntiDetectionLib|MiniVisorPkg/Library/MiniVisorAntiDetectionLib/MiniVisorAntiDetectionLib.inf
  
  # VT-d emulator and hardware collector dependency libraries
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  FileHandleLib|MdePkg/Library/UefiFileHandleLib/UefiFileHandleLib.inf
  ShellLib|ShellPkg/Library/UefiShellLib/UefiShellLib.inf
  HiiLib|MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
  UefiHiiServicesLib|MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  SortLib|MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf

[Components]
  MiniVisorPkg/Library/MiniVisorAuthLib/MiniVisorAuthLib.inf
  MiniVisorPkg/Library/UnifiedAuthLib/UnifiedAuthLib.inf
  MiniVisorPkg/Library/MiniVisorAntiDetectionLib/MiniVisorAntiDetectionLib.inf
  MiniVisorPkg/Drivers/MiniVisorDxe/MiniVisorDxe.inf
  MiniVisorPkg/Drivers/MiniVisorSvmDxe/MiniVisorSvmDxe.inf
  # Keep only the main HardwareCollector variant in the build
  MiniVisorPkg/Tools/HardwareCollector/HardwareCollector.inf

[BuildOptions]
  # Compiler optimization flags
  MSFT:*_*_X64_CC_FLAGS = /O2 /Oi- /DVMX_SUPPORT=1 /DNESTED_VMX=1
  GCC:*_*_X64_CC_FLAGS = -O2 -flto -DVMX_SUPPORT=1 -DNESTED_VMX=1

  # Debug symbols for debugging builds
  MSFT:DEBUG_*_X64_CC_FLAGS = /Zi /Od /DDEBUG_BUILD=1
  GCC:DEBUG_*_X64_CC_FLAGS = -g -O0 -DDEBUG_BUILD=1

  # Assembly flags
  MSFT:*_*_X64_ASM_FLAGS = /DVMX_SUPPORT=1 /DNESTED_VMX=1
  GCC:*_*_X64_ASM_FLAGS = -DVMX_SUPPORT=1 -DNESTED_VMX=1

  # Linker flags - improved alignment and optimization
  MSFT:*_*_X64_DLINK_FLAGS = /ALIGN:4096 /OPT:REF /OPT:ICF
  GCC:*_*_X64_DLINK_FLAGS = -Wl,--gc-sections

  # Warning control - remove recursive macro reference
  MSFT:*_*_X64_CC_FLAGS = /W3 /WX- /Oi- /wd4996 /wd4100 /wd4189
  GCC:*_*_X64_CC_FLAGS = -Wall -Wno-error -Wno-unused-parameter -Wno-unused-variable

  # Disable MSVC intrinsics for CryptoPkg IntrinsicLib to avoid redefining
  # memcpy/memset/memcmp as intrinsics which causes C2169 errors
  CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf|MSFT:*_*_X64_CC_FLAGS = /Oi-

[Packages]
  MdePkg/MdePkg.dec
  UefiCpuPkg/UefiCpuPkg.dec
  ShellPkg/ShellPkg.dec
  MdeModulePkg/MdeModulePkg.dec
  CryptoPkg/CryptoPkg.dec

# Performance optimization for different targets
[BuildOptions.X64.DEBUG]
  MSFT:*_*_X64_CC_FLAGS = /Od /Zi /Oi- /DDEBUG_BUILD=1 /DVMX_SUPPORT=1 /DNESTED_VMX=1 /W3 /WX-
  GCC:*_*_X64_CC_FLAGS = -O0 -g -DDEBUG_BUILD=1 -DVMX_SUPPORT=1 -DNESTED_VMX=1 -Wall -Wno-error
  MSFT:*_*_X64_ASM_FLAGS = /DVMX_SUPPORT=1 /DNESTED_VMX=1
  GCC:*_*_X64_ASM_FLAGS = -DVMX_SUPPORT=1 -DNESTED_VMX=1
  MSFT:*_*_X64_DLINK_FLAGS = /DEBUG /ALIGN:4096 /LTCG:OFF

[BuildOptions.X64.RELEASE]
  MSFT:*_*_X64_CC_FLAGS = /O2 /Oi- /DRELEASE_BUILD=1 /DVMX_SUPPORT=1 /DNESTED_VMX=1 /W3 /WX-
  GCC:*_*_X64_CC_FLAGS = -O2 -flto -DRELEASE_BUILD=1 -DVMX_SUPPORT=1 -DNESTED_VMX=1 -Wall -Wno-error
  MSFT:*_*_X64_ASM_FLAGS = /DVMX_SUPPORT=1 /DNESTED_VMX=1
  GCC:*_*_X64_ASM_FLAGS = -DVMX_SUPPORT=1 -DNESTED_VMX=1
  MSFT:*_*_X64_DLINK_FLAGS = /ALIGN:4096 /OPT:REF /OPT:ICF

[PcdsFixedAtBuild]
  # Base PCD configuration
  gEfiMdePkgTokenSpaceGuid.PcdMaximumUnicodeStringLength|1000000
  gEfiMdePkgTokenSpaceGuid.PcdMaximumAsciiStringLength|1000000
  gEfiMdePkgTokenSpaceGuid.PcdMaximumLinkedListLength|1000000
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x0f
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000000
  
  # MiniVisor specific PCDs
  gMiniVisorPkgTokenSpaceGuid.PcdRing2VirtualizationEnabled|TRUE
  gMiniVisorPkgTokenSpaceGuid.PcdNestedVmxSupported|TRUE
  gMiniVisorPkgTokenSpaceGuid.PcdEptSupported|TRUE
  gMiniVisorPkgTokenSpaceGuid.PcdVpidSupported|TRUE
  gMiniVisorPkgTokenSpaceGuid.PcdVmfuncSupported|TRUE
  gMiniVisorPkgTokenSpaceGuid.PcdMaxNestedVmcsCount|4
  gMiniVisorPkgTokenSpaceGuid.PcdMaxVmcsCount|4
  gMiniVisorPkgTokenSpaceGuid.PcdVmxRegionSize|4096
  gMiniVisorPkgTokenSpaceGuid.PcdVmcsSize|4096
  gMiniVisorPkgTokenSpaceGuid.PcdDebugLevel|3
  gMiniVisorPkgTokenSpaceGuid.PcdStatisticsEnabled|TRUE
  gEfiMdePkgTokenSpaceGuid.PcdReportStatusCodePropertyMask|0x07



[PcdsPatchableInModule]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x2f
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x800fee0f

[UserExtensions.TianoCore."ExtraFiles"]
  MiniVisorPkg/MiniVisorPkg.uni
