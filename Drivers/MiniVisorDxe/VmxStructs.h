#ifndef VMX_STRUCTS_H
#define VMX_STRUCTS_H

#include <Uefi.h>
#include <Library/BaseLib.h>

// Removed duplicate IA32_DESCRIPTOR struct; use the one in BaseLib.h

// VMX Basic MSR 
typedef struct _VMX_BASIC_MSR {
  UINT32 RevisionId;
  UINT32 RegionSize;
  UINT32 RegionClear;
  UINT32 SupportedIA32;
  UINT32 SupportedVmxCap;
  UINT32 SupportedVmxMisc;
  UINT32 SupportedVmxEptVpid;
} VMX_BASIC_MSR;

// VM Exit 
typedef struct _VM_EXIT_INFO {
  UINT32 ExitReason;
  UINT32 ExitQualification;
  UINT32 GuestLinearAddress;
  UINT32 GuestPhysicalAddress;
  UINT32 InstructionLength;
  UINT32 InstructionInfo;
} VM_EXIT_INFO;

//  VMX 
typedef struct _NESTED_VMX_CONTEXT {
  UINT64 HostRsp;
  UINT64 HostRip;
  UINT64 GuestRsp;
  UINT64 GuestRip;
  UINT64 GuestRax;
  UINT64 GuestRcx;
  UINT64 GuestRdx;
  UINT64 GuestRbx;
  UINT64 GuestRbp;
  UINT64 GuestRsi;
  UINT64 GuestRdi;
  UINT64 GuestR8;
  UINT64 GuestR9;
  UINT64 GuestR10;
  UINT64 GuestR11;
  UINT64 GuestR12;
  UINT64 GuestR13;
  UINT64 GuestR14;
  UINT64 GuestR15;
} NESTED_VMX_CONTEXT;

// Ring-2 VMX 
typedef struct _RING2_VMX_STATE {
  BOOLEAN VmxEnabled;
  BOOLEAN NestedVmxEnabled;
  UINT32 VmxRevisionId;
  UINT64 VmxRegion;
  UINT64 VmxRegionSize;
  UINT64 Vmcs;
  UINT64 VmcsSize;
  UINT64 EptPageTable;
  UINT64 EptPageTableSize;
  UINT64 MsrBitmap;
  UINT64 IoBitmapA;
  UINT64 IoBitmapB;
  UINT64 Vpid;
  UINT64 VmxCapabilities;
} RING2_VMX_STATE;

//  VMCS 
typedef struct _NESTED_VMCS {
  UINT64 RevisionId;
  UINT64 AbortIndicator;
  UINT64 Data[1024];  // VMCS 
} NESTED_VMCS;

// Ring-2 
typedef struct _RING2_VIRTUALIZATION_MANAGER {
  RING2_VMX_STATE VmxState;
  NESTED_VMX_CONTEXT NestedContext;
  NESTED_VMCS *NestedVmcs;
  UINT32 NestedVmcsCount;
  UINT32 MaxNestedVmcsCount;
  BOOLEAN EptSupported;
  BOOLEAN VpidSupported;
  BOOLEAN VmfuncSupported;
  UINT32 DebugLevel;
  BOOLEAN StatisticsEnabled;
} RING2_VIRTUALIZATION_MANAGER;

// VM Exit 
typedef EFI_STATUS (*VM_EXIT_HANDLER)(
  IN UINT32 ExitReason,
  IN VM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_VMX_CONTEXT *Context
);

// Ring-2 Exit 
typedef EFI_STATUS (*RING2_EXIT_HANDLER)(
  IN UINT32 ExitReason,
  IN VM_EXIT_INFO *ExitInfo,
  IN OUT RING2_VIRTUALIZATION_MANAGER *Manager
);

//  VMX 
typedef struct _NESTED_VMX_CAPABILITIES {
  UINT32 VmxBasic;
  UINT32 VmxPinBased;
  UINT32 VmxProcBased;
  UINT32 VmxProcBased2;
  UINT32 VmxExit;
  UINT32 VmxEntry;
  UINT32 VmxMisc;
  UINT32 VmxCr0Fixed0;
  UINT32 VmxCr0Fixed1;
  UINT32 VmxCr4Fixed0;
  UINT32 VmxCr4Fixed1;
  UINT32 VmxVmcsEnum;
  UINT32 VmxEptVpidCap;
} NESTED_VMX_CAPABILITIES;

// Ring-2 
typedef struct _RING2_MEMORY_REGION {
  UINT64 BaseAddress;
  UINT64 Size;
  UINT32 Type;
  BOOLEAN Allocated;
} RING2_MEMORY_REGION;

// Ring-2 
typedef struct _RING2_INTERRUPT_GATE {
  UINT64 Offset;
  UINT16 Selector;
  UINT16 Attributes;
  UINT16 Reserved;
  UINT32 Reserved2;
} RING2_INTERRUPT_GATE;

// EPT 
typedef struct _EPT_PML4E {
  UINT64 Read : 1;
  UINT64 Write : 1;
  UINT64 Execute : 1;
  UINT64 Reserved1 : 5;
  UINT64 Accessed : 1;
  UINT64 Reserved2 : 3;
  UINT64 UserModeExecute : 1;
  UINT64 Reserved3 : 1;
  UINT64 PhysicalAddress : 40;
  UINT64 Reserved4 : 12;
} EPT_PML4E;

typedef struct _EPT_PDPTE {
  UINT64 Read : 1;
  UINT64 Write : 1;
  UINT64 Execute : 1;
  UINT64 Reserved1 : 5;
  UINT64 Accessed : 1;
  UINT64 Reserved2 : 3;
  UINT64 UserModeExecute : 1;
  UINT64 Reserved3 : 1;
  UINT64 PhysicalAddress : 40;
  UINT64 Reserved4 : 12;
} EPT_PDPTE;

typedef struct _EPT_PDE {
  UINT64 Read : 1;
  UINT64 Write : 1;
  UINT64 Execute : 1;
  UINT64 Reserved1 : 5;
  UINT64 Accessed : 1;
  UINT64 Reserved2 : 3;
  UINT64 UserModeExecute : 1;
  UINT64 Reserved3 : 1;
  UINT64 PhysicalAddress : 40;
  UINT64 Reserved4 : 12;
} EPT_PDE;

typedef struct _EPT_PTE {
  UINT64 Read : 1;
  UINT64 Write : 1;
  UINT64 Execute : 1;
  UINT64 MemoryType : 3;
  UINT64 IgnorePat : 1;
  UINT64 LargePage : 1;
  UINT64 Accessed : 1;
  UINT64 Dirty : 1;
  UINT64 UserModeExecute : 1;
  UINT64 Reserved1 : 1;
  UINT64 PhysicalAddress : 40;
  UINT64 Reserved2 : 12;
} EPT_PTE;

// VTD (Virtualization Technology for Directed I/O) 

// ACPI DMAR 
typedef struct _ACPI_DMAR_HEADER {
  UINT32 Signature;
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
} ACPI_DMAR_HEADER;

// VTD 
typedef struct _VTD_ROOT_TABLE_ENTRY {
  UINT64 Present : 1;
  UINT64 Reserved1 : 11;
  UINT64 ContextTablePointer : 52;
} VTD_ROOT_TABLE_ENTRY;

// VTD 
typedef struct _VTD_CONTEXT_TABLE_ENTRY {
  UINT64 Present : 1;
  UINT64 FaultProcessingDisable : 1;
  UINT64 TranslationType : 2;
  UINT64 Reserved1 : 8;
  UINT64 SecondLevelPageTablePointer : 52;
  UINT64 AddressWidth : 3;
  UINT64 Reserved2 : 4;
  UINT64 DomainId : 16;
  UINT64 Reserved3 : 32;
  UINT64 Reserved4 : 64;
} VTD_CONTEXT_TABLE_ENTRY;

// VTD  (4)
typedef struct _VTD_PAGE_TABLE_ENTRY_4K {
  UINT64 Present : 1;
  UINT64 ReadWrite : 1;
  UINT64 UserSupervisor : 1;
  UINT64 WriteThrough : 1;
  UINT64 CacheDisable : 1;
  UINT64 Accessed : 1;
  UINT64 Dirty : 1;
  UINT64 PageSize : 1;
  UINT64 Global : 1;
  UINT64 Reserved1 : 2;
  UINT64 ProtectionKey : 4;
  UINT64 PhysicalAddress : 40;  // Fixed: 40 bits for physical address
  UINT64 Reserved2 : 12;
} VTD_PAGE_TABLE_ENTRY_4K;

// VTD 
typedef struct _VTD_INTERRUPT_REMAP_TABLE_ENTRY {
  UINT64 Present : 1;
  UINT64 DestinationMode : 1;
  UINT64 RedirectionHint : 1;
  UINT64 TriggerMode : 1;
  UINT64 DeliveryMode : 3;
  UINT64 Reserved1 : 1;
  UINT64 Destination : 8;
  UINT64 Reserved2 : 8;
  UINT64 Vector : 8;
  UINT64 Reserved3 : 32;
} VTD_INTERRUPT_REMAP_TABLE_ENTRY;

// VTD device scope
typedef struct _VTD_DEVICE_SCOPE {
  UINT8  Type;
  UINT8  Length;
  UINT16 Reserved;
  UINT8  EnumerationId;
  UINT8  StartBusNumber;
} VTD_DEVICE_SCOPE;

// VTD DRHD (DMA Remapping Hardware Unit Definition)
typedef struct _VTD_DRHD {
  UINT16 Type;
  UINT16 Length;
  UINT8  Flags;
  UINT8  Reserved;
  UINT16 SegmentNumber;
  UINT64 RegisterBaseAddress;
  VTD_DEVICE_SCOPE DeviceScope[1];
} VTD_DRHD;

// VTD RMRR (Reserved Memory Region Reporting)
typedef struct _VTD_RMRR {
  UINT16 Type;
  UINT16 Length;
  UINT16 SegmentNumber;
  UINT64 ReservedMemoryRegionBaseAddress;
  UINT64 ReservedMemoryRegionLimitAddress;
  VTD_DEVICE_SCOPE DeviceScope[1];
} VTD_RMRR;

// VTD 
typedef struct _VTD_MANAGER {
  BOOLEAN Initialized;
  BOOLEAN Enabled;
  UINT32  SegmentCount;
  UINT32  DomainCount;
  UINT64  RootTableAddress;
  UINT64  ContextTableAddress;
  UINT64  InterruptRemapTableAddress;
  UINT64  RootTableSize;
  UINT64  ContextTableSize;
  UINT64  InterruptRemapTableSize;
  UINT64  RegisterBaseAddress;  // VTD register base address
  UINT64  CapabilityRegister;
  UINT64  ExtendedCapabilityRegister;
  UINT64  GlobalCommandRegister;
  UINT64  GlobalStatusRegister;
  UINT64  RootTableAddressRegister;
  UINT64  ContextCommandRegister;
  UINT64  FaultStatusRegister;
  UINT64  FaultEventControlRegister;
  UINT64  FaultEventDataRegister;
  UINT64  FaultEventAddressRegister;
  UINT64  FaultEventUpperAddressRegister;
  // Enhanced VTD features
  UINT32  FeatureFlags;
  UINT32  ProtectionFlags;
  UINT64  PerformanceCounter;
  UINT64  ErrorStatus;
  UINT32  MaxDomains;
  UINT32  MaxDevices;
  BOOLEAN RealTimeProtectionEnabled;
  BOOLEAN AntiDetectionEnabled;
  UINT64  LastAccessTime;
  // Additional fields used by MiniVisorDxe.c
  UINTN   DmarTableKey;
  BOOLEAN IsEnabled;
  UINT64  MmioBase;
  BOOLEAN PerformanceOptimizations;
  UINT32  CachePolicy;
  BOOLEAN LatencyOptimization;
  UINT64  MinLatency;
  UINT64  MaxLatency;
  UINT64  AverageLatency;
  UINT32  OperatingFrequency;
  BOOLEAN CompatibilityMode;
  // Timestamp of last anti-debug detection to support decay
  UINT64  LastAntiDebugTsc;
} VTD_MANAGER;

// VTD 
typedef struct _VTD_DOMAIN {
  UINT32 DomainId;
  UINT64 ContextTableEntry;
  UINT64 SecondLevelPageTableAddress;
  UINT64 SecondLevelPageTableSize;
  BOOLEAN Active;
  UINT32 DeviceCount;
  UINT16 AssignedDevices[256]; // Supports up to 256 devices
} VTD_DOMAIN;

// VTD device
typedef struct _VTD_DEVICE {
  UINT16 SegmentNumber;
  UINT8  BusNumber;
  UINT8  DeviceNumber;
  UINT8  FunctionNumber;
  UINT32 DomainId;
  BOOLEAN Active;
  UINT64 ContextTableEntry;
} VTD_DEVICE;

// VTD 
typedef struct _VTD_INTERRUPT_REMAP {
  UINT32 SourceId;
  UINT8  Vector;
  UINT8  DeliveryMode;
  UINT8  DestinationMode;
  UINT8  TriggerMode;
  UINT8  Destination;
  BOOLEAN Active;
  UINT64 InterruptRemapTableEntry;
} VTD_INTERRUPT_REMAP;

// VTD Real-time Protection Context
typedef struct _VTD_PROTECTION_CONTEXT {
  UINT32  ProtectionFlags;
  BOOLEAN AntiDebugEnabled;
  BOOLEAN AntiDumpEnabled;
  BOOLEAN AntiHookEnabled;
  BOOLEAN AntiVmDetectEnabled;
  BOOLEAN MemoryEncryptionEnabled;
  BOOLEAN CodeIntegrityEnabled;
  UINT64  LastCheckTime;
  UINT32  ProtectionLevel;
  UINT64  ProtectionKey;
} VTD_PROTECTION_CONTEXT;

// VTD Detection Countermeasures
typedef struct _VTD_DETECTION_COUNTERMEASURES {
  BOOLEAN CpuidSpoofingEnabled;
  BOOLEAN MsrSpoofingEnabled;
  BOOLEAN TimingAttackProtection;
  BOOLEAN CacheTimingProtection;
  BOOLEAN BranchPredictionMasking;
  BOOLEAN HypervisorSignatureHiding;
  BOOLEAN VmwareDetectionMasking;
  BOOLEAN VirtualBoxDetectionMasking;
  BOOLEAN QemuDetectionMasking;
  BOOLEAN XenDetectionMasking;
  UINT32  DetectionCounterMask;
  UINT64  LastDetectionAttempt;
} VTD_DETECTION_COUNTERMEASURES;

// VTD Performance Monitoring
typedef struct _VTD_PERFORMANCE_MONITOR {
  UINT64  CpuidCallCount;
  UINT64  MsrReadCount;
  UINT64  MsrWriteCount;
  UINT64  VmExitCount;
  UINT64  PageFaultCount;
  UINT64  InterruptCount;
  UINT64  TotalProcessingTime;
  UINT64  AverageExitTime;
  UINT64  MaxExitTime;
  UINT64  MinExitTime;
  BOOLEAN MonitoringEnabled;
} VTD_PERFORMANCE_MONITOR;

// Enhanced VTD Manager for Real Machine Testing
typedef struct _VTD_ENHANCED_MANAGER {
  VTD_MANAGER                   BaseManager;
  VTD_PROTECTION_CONTEXT        ProtectionContext;
  VTD_DETECTION_COUNTERMEASURES DetectionCountermeasures;
  VTD_PERFORMANCE_MONITOR       PerformanceMonitor;
  BOOLEAN                       RealMachineMode;
  BOOLEAN                       CompatibilityMode;
  UINT32                        TestingFlags;
  UINT64                        SessionStartTime;
} VTD_ENHANCED_MANAGER;

#endif // VMX_STRUCTS_H
