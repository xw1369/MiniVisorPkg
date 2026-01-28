#ifndef SVM_STRUCTS_H
#define SVM_STRUCTS_H

#include <Uefi.h>
#include <Library/BaseLib.h>

// SVM Segment Descriptor
typedef struct _SVM_SEGMENT_DESCRIPTOR {
  UINT16 Selector;
  UINT16 Attributes;
  UINT32 Limit;
  UINT64 Base;
} SVM_SEGMENT_DESCRIPTOR;

// VMCB Control Area Structure
typedef struct _VMCB_CONTROL_AREA {
  // Intercept vectors
  UINT32 InterceptCrRead;           // 0x000 - CR read intercepts
  UINT32 InterceptCrWrite;          // 0x004 - CR write intercepts
  UINT32 InterceptDrRead;           // 0x008 - DR read intercepts
  UINT32 InterceptDrWrite;          // 0x00C - DR write intercepts
  UINT32 InterceptException;        // 0x010 - Exception intercepts
  UINT32 InterceptInstr1;           // 0x014 - Instruction intercepts (set 1)
  UINT32 InterceptInstr2;           // 0x018 - Instruction intercepts (set 2)
  UINT32 InterceptInstr3;           // 0x01C - Instruction intercepts (set 3)
  UINT8  Reserved1[0x3C - 0x20];    // 0x020 - Reserved
  UINT16 PauseFilterThreshold;      // 0x03C - Pause filter threshold
  UINT16 PauseFilterCount;          // 0x03E - Pause filter count
  UINT64 IopmBasePa;                // 0x040 - IOPM base address
  UINT64 MsrpmBasePa;               // 0x048 - MSRPM base address
  UINT64 TscOffset;                 // 0x050 - TSC offset
  UINT32 Asid;                      // 0x058 - ASID
  UINT32 TlbControl;                // 0x05C - TLB control
  UINT64 VirtualIntr;               // 0x060 - Virtual interrupt
  UINT64 InterruptShadow;           // 0x068 - Interrupt shadow
  UINT64 ExitCode;                  // 0x070 - Exit code
  UINT64 ExitInfo1;                 // 0x078 - Exit info 1
  UINT64 ExitInfo2;                 // 0x080 - Exit info 2
  UINT64 ExitIntInfo;               // 0x088 - Exit interrupt info
  UINT64 NestedPageEnable;          // 0x090 - Nested page enable
  UINT64 AvicApicBar;               // 0x098 - AVIC APIC BAR
  UINT64 AvicLogicalTable;          // Extended: AVIC logical table base (project-specific)
  UINT64 AvicPhysicalTable;         // Extended: AVIC physical table base (project-specific)
  UINT64 GhcbPa;                    // 0x0A0 - GHCB physical address
  UINT64 EventInj;                  // 0x0A8 - Event injection
  UINT64 NestedCr3;                 // 0x0B0 - Nested CR3
  UINT64 LbrVirtualizationEnable;   // 0x0B8 - LBR virtualization enable
  UINT64 VmcbClean;                 // 0x0C0 - VMCB clean bits
  UINT64 NextRip;                   // 0x0C8 - Next RIP
  UINT64 TscMultiplier;             // Extended: TSC scaling multiplier (project-specific)
  UINT8  GuestInstructionBytes[15]; // 0x0D0 - Guest instruction bytes
  UINT8  GuestInstructionLen;       // 0x0DF - Guest instruction length
  UINT64 GuestApicId;               // 0x0E0 - Guest APIC ID
  UINT8  Reserved2[0x400 - 0x0E8];  // 0x0E8 - Reserved
} VMCB_CONTROL_AREA;

// Provide field-name compatibility used in C source
#define VmcbCleanBits VmcbClean
// Back-compat: some C code referenced these alt names; keep aliases to actual fields
#define AvicApicBarLogicalTable AvicLogicalTable
#define AvicApicBarPhysicalTable AvicPhysicalTable

// VMCB State Save Area Structure
typedef struct _VMCB_STATE_SAVE_AREA {
  SVM_SEGMENT_DESCRIPTOR Es;        // 0x400 - ES segment
  SVM_SEGMENT_DESCRIPTOR Cs;        // 0x410 - CS segment
  SVM_SEGMENT_DESCRIPTOR Ss;        // 0x420 - SS segment
  SVM_SEGMENT_DESCRIPTOR Ds;        // 0x430 - DS segment
  SVM_SEGMENT_DESCRIPTOR Fs;        // 0x440 - FS segment
  SVM_SEGMENT_DESCRIPTOR Gs;        // 0x450 - GS segment
  SVM_SEGMENT_DESCRIPTOR Gdtr;      // 0x460 - GDTR
  SVM_SEGMENT_DESCRIPTOR Ldtr;      // 0x470 - LDTR
  SVM_SEGMENT_DESCRIPTOR Idtr;      // 0x480 - IDTR
  SVM_SEGMENT_DESCRIPTOR Tr;        // 0x490 - TR
  UINT8  Reserved1[0x4CB - 0x4A0];  // 0x4A0 - Reserved
  UINT8  Cpl;                       // 0x4CB - Current privilege level
  UINT32 Reserved2;                 // 0x4CC - Reserved
  UINT64 Efer;                      // 0x4D0 - EFER
  UINT8  Reserved3[0x548 - 0x4D8];  // 0x4D8 - Reserved
  UINT64 Cr4;                       // 0x548 - CR4
  UINT64 Cr3;                       // 0x550 - CR3
  UINT64 Cr0;                       // 0x558 - CR0
  UINT64 Dr7;                       // 0x560 - DR7
  UINT64 Dr6;                       // 0x568 - DR6
  UINT64 Rflags;                    // 0x570 - RFLAGS
  UINT64 Rip;                       // 0x578 - RIP
  UINT8  Reserved4[0x5D8 - 0x580];  // 0x580 - Reserved
  UINT64 Rsp;                       // 0x5D8 - RSP
  UINT8  Reserved5[0x5F8 - 0x5E0];  // 0x5E0 - Reserved
  UINT64 Rax;                       // 0x5F8 - RAX
  UINT64 Star;                      // 0x600 - STAR
  UINT64 LStar;                     // 0x608 - LSTAR
  UINT64 CStar;                     // 0x610 - CSTAR
  UINT64 SfMask;                    // 0x618 - SFMASK
  UINT64 KernelGsBase;              // 0x620 - KERNEL_GS_BASE
  UINT64 SysenterCs;                // 0x628 - SYSENTER_CS
  UINT64 SysenterEsp;               // 0x630 - SYSENTER_ESP
  UINT64 SysenterEip;               // 0x638 - SYSENTER_EIP
  UINT64 Cr2;                       // 0x640 - CR2
  UINT8  Reserved6[0x668 - 0x648];  // 0x648 - Reserved
  UINT64 GPat;                      // 0x668 - G_PAT
  UINT64 DbgCtl;                    // 0x670 - DBGCTL
  UINT64 BrFrom;                    // 0x678 - BR_FROM
  UINT64 BrTo;                      // 0x680 - BR_TO
  UINT64 LastExcpFrom;              // 0x688 - LAST_EXCP_FROM
  UINT64 LastExcpTo;                // 0x690 - LAST_EXCP_TO
} VMCB_STATE_SAVE_AREA;

// Complete VMCB Structure
typedef struct _VMCB {
  VMCB_CONTROL_AREA ControlArea;
  VMCB_STATE_SAVE_AREA StateSaveArea;
  UINT8 Reserved[0x1000 - sizeof(VMCB_CONTROL_AREA) - sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB;

// SVM Exit Information
typedef struct _SVM_EXIT_INFO {
  UINT64 ExitCode;
  UINT64 ExitInfo1;
  UINT64 ExitInfo2;
  UINT64 ExitIntInfo;
  UINT64 NextRip;
  UINT32 ExitInstructionLength;
  UINT8  ExitInstructionBytes[15];
} SVM_EXIT_INFO;

// SVM Guest Context for nested virtualization
typedef struct _NESTED_SVM_CONTEXT {
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
  UINT64 GuestRflags;
} NESTED_SVM_CONTEXT;

// Ring-2 SVM State
typedef struct _RING2_SVM_STATE {
  BOOLEAN SvmEnabled;
  BOOLEAN NestedSvmEnabled;
  UINT32  SvmRevisionId;
  UINT64  VmcbRegion;
  UINT64  VmcbRegionSize;
  UINT64  Vmcb;
  UINT64  VmcbSize;
  UINT64  HostSaveArea;
  UINT64  HostSaveAreaSize;
  UINT64  NptPageTable;
  UINT64  NptPageTableSize;
  UINT64  MsrBitmap;
  UINT64  IoBitmap;
  UINT32  Asid;
  UINT64  SvmCapabilities;
} RING2_SVM_STATE;

// Nested VMCB for SVM
typedef struct _NESTED_VMCB {
  VMCB VmcbData;
  UINT64 GuestVmcbPa;
  BOOLEAN Active;
  UINT32 Asid;
} NESTED_VMCB;

// Ring-2 SVM Virtualization Manager
typedef struct _RING2_SVM_MANAGER {
  RING2_SVM_STATE SvmState;
  NESTED_SVM_CONTEXT NestedContext;
  NESTED_VMCB *NestedVmcb;
  UINT32 NestedVmcbCount;
  UINT32 MaxNestedVmcbCount;
  BOOLEAN NptSupported;
  BOOLEAN AsidSupported;
  BOOLEAN DecodeAssistsSupported;
  BOOLEAN NextRipSaveSupported;
  BOOLEAN VmcbCleanSupported;
  BOOLEAN PauseFilterSupported;
  BOOLEAN TscRateSupported;
  BOOLEAN LbrVirtSupported;
  UINT32 DebugLevel;
  BOOLEAN StatisticsEnabled;
  UINT32 MaxAsid;
  UINT64 NptPml4Base;
} RING2_SVM_MANAGER;

// SVM Exit Handler Function Type
typedef EFI_STATUS (*SVM_EXIT_HANDLER)(
  IN UINT64 ExitCode,
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
);

// Ring-2 SVM Exit Handler Function Type
typedef EFI_STATUS (*RING2_SVM_EXIT_HANDLER)(
  IN UINT64 ExitCode,
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT RING2_SVM_MANAGER *Manager
);

// SVM Capabilities Structure
typedef struct _SVM_CAPABILITIES {
  BOOLEAN SvmSupported;
  BOOLEAN NestedPagingSupported;
  BOOLEAN LbrVirtualizationSupported;
  BOOLEAN SvmLockSupported;
  BOOLEAN NextRipSaveSupported;
  BOOLEAN TscRateMsrSupported;
  BOOLEAN VmcbCleanSupported;
  BOOLEAN FlushByAsidSupported;
  BOOLEAN DecodeAssistsSupported;
  BOOLEAN PauseFilterSupported;
  BOOLEAN PauseFilterThresholdSupported;
  BOOLEAN AvicSupported;
  BOOLEAN VirtualVmsaveVmloadSupported;
  BOOLEAN VgifSupported;
  BOOLEAN GmetSupported;
  BOOLEAN NestedSvmSupported; // Add explicit nested SVM support flag
  UINT32 MaxAsid;
  UINT32 MaxNestedPageTableLevels;
} SVM_CAPABILITIES;

// Ring-2 Memory Region for SVM
typedef struct _RING2_SVM_MEMORY_REGION {
  UINT64 BaseAddress;
  UINT64 Size;
  UINT32 Type;
  BOOLEAN Allocated;
  UINT32 Asid;
} RING2_SVM_MEMORY_REGION;

// Ring-2 Interrupt Gate for SVM
typedef struct _RING2_SVM_INTERRUPT_GATE {
  UINT64 Offset;
  UINT16 Selector;
  UINT16 Attributes;
  UINT16 Reserved;
  UINT32 Reserved2;
} RING2_SVM_INTERRUPT_GATE;

// NPT (Nested Page Table) Entry Structures
typedef struct _NPT_PML4E {
  UINT64 Present : 1;
  UINT64 Write : 1;
  UINT64 User : 1;
  UINT64 WriteThrough : 1;
  UINT64 CacheDisable : 1;
  UINT64 Accessed : 1;
  UINT64 Reserved1 : 6;
  UINT64 PhysicalAddress : 40;
  UINT64 Reserved2 : 12;
} NPT_PML4E;

typedef struct _NPT_PDPTE {
  UINT64 Present : 1;
  UINT64 Write : 1;
  UINT64 User : 1;
  UINT64 WriteThrough : 1;
  UINT64 CacheDisable : 1;
  UINT64 Accessed : 1;
  UINT64 Dirty : 1;
  UINT64 PageSize : 1;
  UINT64 Reserved1 : 4;
  UINT64 PhysicalAddress : 40;
  UINT64 Reserved2 : 12;
} NPT_PDPTE;

typedef struct _NPT_PDE {
  UINT64 Present : 1;
  UINT64 Write : 1;
  UINT64 User : 1;
  UINT64 WriteThrough : 1;
  UINT64 CacheDisable : 1;
  UINT64 Accessed : 1;
  UINT64 Dirty : 1;
  UINT64 PageSize : 1;
  UINT64 Reserved1 : 4;
  UINT64 PhysicalAddress : 40;
  UINT64 Reserved2 : 12;
} NPT_PDE;

typedef struct _NPT_PTE {
  UINT64 Present : 1;
  UINT64 Write : 1;
  UINT64 User : 1;
  UINT64 WriteThrough : 1;
  UINT64 CacheDisable : 1;
  UINT64 Accessed : 1;
  UINT64 Dirty : 1;
  UINT64 Reserved1 : 5;
  UINT64 PhysicalAddress : 40;
  UINT64 Reserved2 : 12;
} NPT_PTE;

// IOMMU (I/O Memory Management Unit) structures for AMD
typedef struct _AMD_IOMMU_DEVICE_TABLE_ENTRY {
  UINT64 Valid : 1;
  UINT64 TranslationValid : 1;
  UINT64 Reserved1 : 5;
  UINT64 ReadWrite : 2;
  UINT64 Reserved2 : 1;
  UINT64 UserSupervisor : 1;
  UINT64 Interrupt : 2;
  UINT64 Reserved3 : 4;
  UINT64 DomainId : 16;
  UINT64 Reserved4 : 16;
  UINT64 PageTableRootPointer : 16;
  UINT64 HostAccessDirty : 1;
  UINT64 GuestAccessDirty : 1;
  UINT64 IoTlbEnable : 1;
  UINT64 SnoopAttribute : 1;
  UINT64 Reserved5 : 1;
  UINT64 CacheCoherent : 1;
  UINT64 IoCtl : 2;
  UINT64 CachePolicy : 1;
  UINT64 SystemManagement : 1;
  UINT64 Reserved6 : 6;
  UINT64 InterruptTableLength : 4;
  UINT64 IgnoreUnmappedInterrupts : 1;
  UINT64 InterruptTableRootPointer : 46;
  UINT64 Reserved7 : 4;
  UINT64 InitializePassthrough : 1;
  UINT64 ExtendedType : 1;
  UINT64 Suppress : 1;
  UINT64 Reserved8 : 1;
  UINT64 IoReadPermission : 1;
  UINT64 IoWritePermission : 1;
  UINT64 Reserved9 : 1;
} AMD_IOMMU_DEVICE_TABLE_ENTRY;

// AMD IOMMU Manager
typedef struct _AMD_IOMMU_MANAGER {
  BOOLEAN Initialized;
  BOOLEAN Enabled;
  UINT64 DeviceTableBase;
  UINT64 CommandBufferBase;
  UINT64 EventLogBase;
  UINT64 ExclusionTableBase;
  UINT64 DeviceTableSize;
  UINT64 CommandBufferSize;
  UINT64 EventLogSize;
  UINT64 ExclusionTableSize;
  UINT64 MmioBase;
  UINT32 Capabilities;
  UINT32 ExtendedFeatures;
  UINT32 MaxDomains;
  UINT32 MaxDevices;
  BOOLEAN PerformanceCountersEnabled;
  UINT64 PerformanceCounter;
} AMD_IOMMU_MANAGER;

// SVM Performance Monitoring
typedef struct _SVM_PERFORMANCE_MONITOR {
  UINT64 VmrunCount;
  UINT64 VmexitCount;
  UINT64 VmmcallCount;
  UINT64 NptViolationCount;
  UINT64 MsrInterceptCount;
  UINT64 IoInterceptCount;
  UINT64 CpuidInterceptCount;
  UINT64 TotalProcessingTime;
  UINT64 AverageExitTime;
  UINT64 MaxExitTime;
  UINT64 MinExitTime;
  BOOLEAN MonitoringEnabled;
} SVM_PERFORMANCE_MONITOR;

// Enhanced SVM Manager for Real Machine Testing
typedef struct _SVM_ENHANCED_MANAGER {
  RING2_SVM_MANAGER BaseManager;
  AMD_IOMMU_MANAGER IommuManager;
  SVM_PERFORMANCE_MONITOR PerformanceMonitor;
  BOOLEAN RealMachineMode;
  BOOLEAN CompatibilityMode;
  UINT32 TestingFlags;
  UINT64 SessionStartTime;
  BOOLEAN AntiDetectionEnabled;
  BOOLEAN MemoryEncryptionEnabled;
  UINT32 ProtectionLevel;
} SVM_ENHANCED_MANAGER;

// SVM Hardware Fingerprint Structure
#pragma pack(1)
typedef struct _SVM_HARDWARE_FINGERPRINT {
  UINT32 CpuSignature;        // CPU signature from CPUID
  UINT32 CpuFeatures;         // CPU features
  UINT32 CpuExtFeatures;      // Extended CPU features
  UINT32 BrandRegs[4];        // CPU brand string registers
  UINT64 SystemTime;          // System time
  UINT64 MemorySize;          // Total memory size
  UINT32 PciDeviceCount;      // Number of PCI devices
  UINT8  MainboardSerial[64]; // Mainboard serial number
  UINT32 BiosVersion;         // BIOS version
  UINT32 ChipsetId;           // Chipset ID
  UINT32 CpuBrandHash;        // CPU brand string hash
  UINT8  CpuSerialNumber[32]; // CPU serial number
  UINT32 MainboardSerialHash; // Mainboard serial hash
  UINT32 Reserved1;           // Reserved field 1
  UINT32 Reserved2;           // Reserved field 2
  UINT32 Reserved[6];         // Reserved for future use
} SVM_HARDWARE_FINGERPRINT;
#pragma pack()

#endif // SVM_STRUCTS_H
