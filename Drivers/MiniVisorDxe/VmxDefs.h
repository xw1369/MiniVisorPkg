#ifndef VMX_DEFS_H
#define VMX_DEFS_H

#include <Uefi.h>
#include <Library/BaseLib.h>

// MSR definitions
#define MSR_IA32_VMX_BASIC                    0x480
#define MSR_IA32_VMX_PINBASED_CTLS            0x481
#define MSR_IA32_VMX_PROCBASED_CTLS           0x482
#define MSR_IA32_VMX_EXIT_CTLS                0x483
#define MSR_IA32_VMX_ENTRY_CTLS               0x484
#define MSR_IA32_VMX_MISC                     0x485
#define MSR_IA32_VMX_CR0_FIXED0               0x486
#define MSR_IA32_VMX_CR0_FIXED1               0x487
#define MSR_IA32_VMX_CR4_FIXED0               0x488
#define MSR_IA32_VMX_CR4_FIXED1               0x489
#define MSR_IA32_VMX_VMCS_ENUM                0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2          0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP             0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS       0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS      0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS           0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS          0x490
#define MSR_IA32_VMX_VMFUNC                   0x491
// Feature control MSR for enabling VMX outside SMX
#define MSR_IA32_FEATURE_CONTROL              0x3A

// VMX Basic MSR bit fields
// SDM: IA32_VMX_BASIC[50:53] encodes the memory type for VMCS structures (WB expected)
#define VMX_BASIC_MEMORY_TYPE_SHIFT           50
#define VMX_BASIC_MEMORY_TYPE_MASK            (0xFULL << VMX_BASIC_MEMORY_TYPE_SHIFT)
#define VMX_BASIC_MEMORY_TYPE_WRITEBACK       (0x6ULL << VMX_BASIC_MEMORY_TYPE_SHIFT)
#define VMX_BASIC_VMCS_SIZE_MASK              0x0000000000001FFF
#define VMX_BASIC_VMCS_SIZE_SHIFT             32
#define VMX_BASIC_VMCS_REVISION_ID_MASK       0x00000000FFFFFFFF

// VMX control bit fields
#define VMX_PROCBASED_CTLS2_EPT               0x0000000000000002
#define VMX_PROCBASED_CTLS2_VPID              0x0000000000000020
#define VMX_PROCBASED_CTLS2_VMFUNC            0x0000000000000040
#define VMX_PROCBASED_CTLS2_VIRTUALIZE_APIC_ACCESSES 0x0000000000000100
#define VMX_PROCBASED_CTLS2_VIRTUALIZE_X2APIC_MODE  0x0000000000000200
#define VMX_PROCBASED_CTLS2_VIRTUALIZE_MSR_ACCESSES 0x0000000000000400
#define VMX_PROCBASED_CTLS2_VIRTUALIZE_IO_ACCESSES  0x0000000000000800

// VMCS fields (16-bit control)
#define VMCS_VPID                             0x0000000C
#define VMCS_VMCS_LINK_POINTER                0x00000010
#define VMCS_PIN_BASED_VM_EXEC_CONTROL        0x00004000
#define VMCS_CPU_BASED_VM_EXEC_CONTROL        0x00004002
#define VMCS_CPU_BASED_VM_EXEC_CONTROL2       0x0000401E
#define VMCS_VM_EXIT_CONTROLS                 0x0000400C
#define VMCS_VM_ENTRY_CONTROLS                0x00004012
#define VMCS_VM_INSTRUCTION_ERROR             0x00004400
#define VMCS_EXIT_REASON                      0x00004402
#define VMCS_VM_EXIT_QUALIFICATION            0x00006400
#define VMCS_IO_RCX                           0x00006402
#define VMCS_IO_RSI                           0x00006404
#define VMCS_IO_RDI                           0x00006406
#define VMCS_IO_RIP                           0x00006408
#define VMCS_GUEST_LINEAR_ADDRESS             0x0000640A
#define VMCS_GUEST_PHYSICAL_ADDRESS           0x0000640C

// VMCS fields (64-bit control)
#define VMCS_MSR_BITMAP                       0x00002004
#define VMCS_IO_BITMAP_A                      0x0000201E
#define VMCS_IO_BITMAP_B                      0x00002020
#define VMCS_EPTP                             0x0000201A

// VMCS fields (32-bit guest state)
#define VMCS_GUEST_ES_SELECTOR                0x00000800
#define VMCS_GUEST_CS_SELECTOR                0x00000802
#define VMCS_GUEST_SS_SELECTOR                0x00000804
#define VMCS_GUEST_DS_SELECTOR                0x00000806
#define VMCS_GUEST_FS_SELECTOR                0x00000808
#define VMCS_GUEST_GS_SELECTOR                0x0000080A
#define VMCS_GUEST_LDTR_SELECTOR              0x0000080C
#define VMCS_GUEST_TR_SELECTOR                0x0000080E
#define VMCS_GUEST_INTERRUPT_STATUS           0x00000810
#define VMCS_GUEST_PML_INDEX                  0x00000812

// VMCS fields (64-bit guest state)
#define VMCS_GUEST_CR0                        0x00006800
#define VMCS_GUEST_CR3                        0x00006802
#define VMCS_GUEST_CR4                        0x00006804
#define VMCS_GUEST_ES_BASE                    0x00006806
#define VMCS_GUEST_CS_BASE                    0x00006808
#define VMCS_GUEST_SS_BASE                    0x0000680A
#define VMCS_GUEST_DS_BASE                    0x0000680C
#define VMCS_GUEST_FS_BASE                    0x0000680E
#define VMCS_GUEST_GS_BASE                    0x00006810
#define VMCS_GUEST_LDTR_BASE                  0x00006812
#define VMCS_GUEST_TR_BASE                    0x00006814
#define VMCS_GUEST_GDTR_BASE                  0x00006816
#define VMCS_GUEST_IDTR_BASE                  0x00006818
#define VMCS_GUEST_DR7                        0x0000681A
#define VMCS_GUEST_RSP                        0x0000681C
#define VMCS_GUEST_RIP                        0x0000681E
#define VMCS_GUEST_RFLAGS                     0x00006820
#define VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS   0x00006822
#define VMCS_GUEST_IA32_SYSENTER_ESP          0x00006824
#define VMCS_GUEST_IA32_SYSENTER_EIP          0x00006826
#define VMCS_GUEST_IA32_SYSENTER_CS           0x00006828
#define VMCS_GUEST_CR0_HIGH                   0x0000682A
#define VMCS_GUEST_CR3_HIGH                   0x0000682C
#define VMCS_GUEST_CR4_HIGH                   0x0000682E
#define VMCS_GUEST_ES_BASE_HIGH               0x00006830
#define VMCS_GUEST_CS_BASE_HIGH               0x00006832
#define VMCS_GUEST_SS_BASE_HIGH               0x00006834
#define VMCS_GUEST_DS_BASE_HIGH               0x00006836
#define VMCS_GUEST_FS_BASE_HIGH               0x00006838
#define VMCS_GUEST_GS_BASE_HIGH               0x0000683A
#define VMCS_GUEST_LDTR_BASE_HIGH             0x0000683C
#define VMCS_GUEST_TR_BASE_HIGH               0x0000683E
#define VMCS_GUEST_GDTR_BASE_HIGH             0x00006840
#define VMCS_GUEST_IDTR_BASE_HIGH             0x00006842
#define VMCS_GUEST_DR7_HIGH                   0x00006844
#define VMCS_GUEST_RSP_HIGH                   0x00006846
#define VMCS_GUEST_RIP_HIGH                   0x00006848
#define VMCS_GUEST_RFLAGS_HIGH                0x0000684A
#define VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS_HIGH 0x0000684C
#define VMCS_GUEST_IA32_SYSENTER_ESP_HIGH     0x0000684E
#define VMCS_GUEST_IA32_SYSENTER_EIP_HIGH     0x00006850
#define VMCS_GUEST_IA32_SYSENTER_CS_HIGH      0x00006852
#define VMCS_GUEST_ACTIVITY_STATE             0x00006826
#define VMCS_GUEST_SMBASE                     0x00006828
#define VMCS_GUEST_IA32_SMM_MONITOR_CTL       0x0000682A
#define VMCS_GUEST_IA32_PAT                   0x0000682C
#define VMCS_GUEST_IA32_EFER                  0x0000682E
#define VMCS_GUEST_IA32_PERF_GLOBAL_CTRL      0x0000682E
#define VMCS_GUEST_PDPTE0                     0x0000682A
#define VMCS_GUEST_PDPTE1                     0x0000682C
#define VMCS_GUEST_PDPTE2                     0x0000682E
#define VMCS_GUEST_PDPTE3                     0x00006830

// VMCS fields (32-bit host state)
#define VMCS_HOST_CR0                         0x00006C00
#define VMCS_HOST_CR3                         0x00006C02
#define VMCS_HOST_CR4                         0x00006C04
#define VMCS_HOST_FS_BASE                     0x00006C06
#define VMCS_HOST_GS_BASE                     0x00006C08
#define VMCS_HOST_TR_BASE                     0x00006C0A
#define VMCS_HOST_GDTR_BASE                   0x00006C0C
#define VMCS_HOST_IDTR_BASE                   0x00006C0E
#define VMCS_HOST_IA32_SYSENTER_ESP           0x00006C10
#define VMCS_HOST_IA32_SYSENTER_EIP           0x00006C12
#define VMCS_HOST_RSP                         0x00006C14
#define VMCS_HOST_RIP                         0x00006C16

// VMCS fields (16-bit host selector state)
#define VMCS_HOST_ES_SELECTOR                 0x00000C00
#define VMCS_HOST_CS_SELECTOR                 0x00000C02
#define VMCS_HOST_SS_SELECTOR                 0x00000C04
#define VMCS_HOST_DS_SELECTOR                 0x00000C06
#define VMCS_HOST_FS_SELECTOR                 0x00000C08
#define VMCS_HOST_GS_SELECTOR                 0x00000C0A
#define VMCS_HOST_TR_SELECTOR                 0x00000C0C

// VMCS fields (64-bit host state)
#define VMCS_HOST_CR0_HIGH                    0x00006C18
#define VMCS_HOST_CR3_HIGH                    0x00006C1A
#define VMCS_HOST_CR4_HIGH                    0x00006C1C
#define VMCS_HOST_FS_BASE_HIGH                0x00006C1E
#define VMCS_HOST_GS_BASE_HIGH                0x00006C20
#define VMCS_HOST_TR_BASE_HIGH                0x00006C22
#define VMCS_HOST_GDTR_BASE_HIGH              0x00006C24
#define VMCS_HOST_IDTR_BASE_HIGH              0x00006C26
#define VMCS_HOST_IA32_SYSENTER_ESP_HIGH      0x00006C28
#define VMCS_HOST_IA32_SYSENTER_EIP_HIGH      0x00006C2A
#define VMCS_HOST_RSP_HIGH                    0x00006C2C
#define VMCS_HOST_RIP_HIGH                    0x00006C2E

// VMCS general-purpose registers
#define VMCS_GUEST_RAX                        0x0000681C
#define VMCS_GUEST_RCX                        0x0000681E
#define VMCS_GUEST_RDX                        0x00006820
#define VMCS_GUEST_RBX                        0x00006822
#define VMCS_GUEST_RBP                        0x00006824
#define VMCS_GUEST_RSI                        0x00006826
#define VMCS_GUEST_RDI                        0x00006828
#define VMCS_GUEST_R8                         0x0000682A
#define VMCS_GUEST_R9                         0x0000682C
#define VMCS_GUEST_R10                        0x0000682E
#define VMCS_GUEST_R11                        0x00006830
#define VMCS_GUEST_R12                        0x00006832
#define VMCS_GUEST_R13                        0x00006834
#define VMCS_GUEST_R14                        0x00006836
#define VMCS_GUEST_R15                        0x00006838
#define VMCS_GUEST_RAX_HIGH                   0x0000683A
#define VMCS_GUEST_RCX_HIGH                   0x0000683C
#define VMCS_GUEST_RDX_HIGH                   0x0000683E
#define VMCS_GUEST_RBX_HIGH                   0x00006840
#define VMCS_GUEST_RBP_HIGH                   0x00006842
#define VMCS_GUEST_RSI_HIGH                   0x00006844
#define VMCS_GUEST_RDI_HIGH                   0x00006846
#define VMCS_GUEST_R8_HIGH                    0x00006848
#define VMCS_GUEST_R9_HIGH                    0x0000684A
#define VMCS_GUEST_R10_HIGH                   0x0000684C
#define VMCS_GUEST_R11_HIGH                   0x0000684E
#define VMCS_GUEST_R12_HIGH                   0x00006850
#define VMCS_GUEST_R13_HIGH                   0x00006852
#define VMCS_GUEST_R14_HIGH                   0x00006854
#define VMCS_GUEST_R15_HIGH                   0x00006856

// VM Exit reasons
#define VM_EXIT_REASON_EXCEPTION_NMI          0
#define VM_EXIT_REASON_EXTERNAL_INTERRUPT     1
#define VM_EXIT_REASON_TRIPLE_FAULT           2
#define VM_EXIT_REASON_INIT                   3
#define VM_EXIT_REASON_SIPI                   4
#define VM_EXIT_REASON_IO_SMI                 5
#define VM_EXIT_REASON_OTHER_SMI              6
#define VM_EXIT_REASON_PENDING_VMX_INTERRUPT  7
#define VM_EXIT_REASON_TASK_SWITCH            9
#define VM_EXIT_REASON_CPUID                  10
#define VM_EXIT_REASON_HLT                    12
#define VM_EXIT_REASON_VMCALL                 18
#define VM_EXIT_REASON_CR_ACCESS              28
#define VM_EXIT_REASON_DR_ACCESS              29
#define VM_EXIT_REASON_IO_INSTRUCTION         30
#define VM_EXIT_REASON_MSR_READ               31
#define VM_EXIT_REASON_MSR_WRITE              32
#define VM_EXIT_REASON_ENTRY_FAILURE_GUEST_STATE 33
#define VM_EXIT_REASON_ENTRY_FAILURE_MSR_LOADING 34
#define VM_EXIT_REASON_MWAIT                  36
#define VM_EXIT_REASON_MONITOR_TRAP_FLAG      37
#define VM_EXIT_REASON_MONITOR                39
#define VM_EXIT_REASON_PAUSE                  40
#define VM_EXIT_REASON_ENTRY_FAILURE_MACHINE_CHECK 41
#define VM_EXIT_REASON_TPR_BELOW_THRESHOLD    43
#define VM_EXIT_REASON_APIC_ACCESS            44
#define VM_EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR 46
#define VM_EXIT_REASON_LDTR_OR_TR_ACCESS      47
#define VM_EXIT_REASON_EPT_VIOLATION          48
#define VM_EXIT_REASON_EPT_MISCONFIGURATION   49
#define VM_EXIT_REASON_INVEPT                 50
#define VM_EXIT_REASON_RDTSCP                 51
#define VM_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED 52
#define VM_EXIT_REASON_INVVPID                53
#define VM_EXIT_REASON_WBINVD                 54
#define VM_EXIT_REASON_XSETBV                 55
#define VM_EXIT_REASON_APIC_WRITE             56
#define VM_EXIT_REASON_RDRAND                 57
#define VM_EXIT_REASON_INVPCID                58
#define VM_EXIT_REASON_VMFUNC                 59
#define VM_EXIT_REASON_ENCLS                  60
#define VM_EXIT_REASON_RDSEED                 61
#define VM_EXIT_REASON_PML_FULL               62
#define VM_EXIT_REASON_XSAVES                 63
#define VM_EXIT_REASON_XRSTORS                64
#define VM_EXIT_REASON_UMWAIT                 67
#define VM_EXIT_REASON_TPAUSE                 68

// Ring-2 nested virtualization
#define RING2_VMX_STATE_DISABLED              0
#define RING2_VMX_STATE_ENABLED               1
#define RING2_VMX_STATE_NESTED_ENABLED        2

#define NESTED_VMX_MAX_VMCS_COUNT             16
#define NESTED_VMX_VMCS_SIZE                  4096
#define NESTED_VMX_VMXON_SIZE                 4096

// Ring-2 privilege levels
#define RING2_PRIVILEGE_LEVEL_0               0
#define RING2_PRIVILEGE_LEVEL_1               1
#define RING2_PRIVILEGE_LEVEL_2               2
#define RING2_PRIVILEGE_LEVEL_3               3

// VMCS 
typedef enum _VMCS_TYPE {
  VMCS_TYPE_16BIT_CONTROL = 0,
  VMCS_TYPE_64BIT_CONTROL = 1,
  VMCS_TYPE_32BIT_GUEST_STATE = 2,
  VMCS_TYPE_64BIT_GUEST_STATE = 3,
  VMCS_TYPE_32BIT_HOST_STATE = 4,
  VMCS_TYPE_64BIT_HOST_STATE = 5
} VMCS_TYPE;

// Compatibility aliases for missing VMCS names
#define VMCS_VM_EXIT_REASON                   VMCS_EXIT_REASON
#define VMCS_EXIT_QUALIFICATION               VMCS_VM_EXIT_QUALIFICATION
#define VMCS_INSTRUCTION_LENGTH               0x0000440C
#define VMCS_INSTRUCTION_INFO                 0x0000440E

// VM Exit reasons (alt set)
#define VM_EXIT_CPUID                         0x0000000A
#define VM_EXIT_MSR_READ                      0x0000001E
#define VM_EXIT_MSR_WRITE                     0x0000001F
#define VM_EXIT_VMCALL                        0x00000012
#define VM_EXIT_CR_ACCESS                     0x0000001C
#define VM_EXIT_DR_ACCESS                     0x0000001D
#define VM_EXIT_IO_INSTRUCTION                0x00000007
#define VM_EXIT_RDTSC                         0x00000010
#define VM_EXIT_RDTSCP                        0x00000011
#define VM_EXIT_VMCLEAR                       0x00000005
#define VM_EXIT_VMLAUNCH                      0x00000006
#define VM_EXIT_VMPTRLD                       0x00000004
#define VM_EXIT_VMPTRST                       0x00000008
#define VM_EXIT_VMREAD                        0x00000009
#define VM_EXIT_VMRESUME                      0x00000007
#define VM_EXIT_VMWRITE                       0x0000000A
#define VM_EXIT_VMXOFF                        0x0000000B
#define VM_EXIT_VMXON                         0x0000000C

// VTD (Virtualization Technology for Directed I/O) constants
// Common VT-d limits
#define VTD_MAX_DOMAINS                       256
#define VTD_MAX_DEVICES_PER_DOMAIN            256

// Cache policy and operating frequency enums used by VT-d manager
#define VTD_CACHE_DEFAULT                      0
#define VTD_CACHE_CONSERVATIVE                 1
#define VTD_CACHE_AGGRESSIVE                   2

#define VTD_FREQ_LOW                           0
#define VTD_FREQ_NORMAL                        1
#define VTD_FREQ_HIGH                          2

// ACPI signatures
#define ACPI_TABLE_SIGNATURE_DMAR    0x52414D44  // "DMAR"
#define ACPI_TABLE_SIGNATURE_DRHD    0x44485244  // "DRHD"
#define ACPI_TABLE_SIGNATURE_RMRR    0x52524D52  // "RMRR"
#define ACPI_TABLE_SIGNATURE_ATSR    0x52535441  // "ATSR"
#define ACPI_TABLE_SIGNATURE_RHSA    0x41534852  // "RHSA"
#define ACPI_TABLE_SIGNATURE_ANDD    0x444E4144  // "ANDD"

// VTD MSR bits
#define MSR_IA32_VMX_PROCBASED_CTLS2_VTD    0x0000000000000080
#define MSR_IA32_VMX_EPT_VPID_CAP_VTD       0x0000000000000100

// VTD registers
#define VTD_CAP_REG                          0x00000000
#define VTD_ECAP_REG                         0x00000008
#define VTD_GCMD_REG                         0x00000018
#define VTD_GSTS_REG                         0x0000001C
#define VTD_RTADDR_REG                       0x00000020
#define VTD_CCMD_REG                         0x00000028
#define VTD_FSTS_REG                         0x00000034
#define VTD_FECTL_REG                        0x00000038
#define VTD_FEDATA_REG                       0x0000003C
#define VTD_FEADDR_REG                       0x00000040
#define VTD_FEUADDR_REG                      0x00000044

// VTD root table entry
#define VTD_ROOT_TABLE_ENTRY_PRESENT         0x00000001
#define VTD_ROOT_TABLE_ENTRY_CONTEXT_PTR     0x000000000000FFF0

// VTD context table entry fields
#define VTD_CONTEXT_TABLE_ENTRY_PRESENT      0x00000001
#define VTD_CONTEXT_TABLE_ENTRY_TT           0x00000002
#define VTD_CONTEXT_TABLE_ENTRY_AW           0x0000000C
#define VTD_CONTEXT_TABLE_ENTRY_DID          0x0000FFFF
#define VTD_CONTEXT_TABLE_ENTRY_DOMAIN_ID    0x0000FFFF

// VTD page table levels
#define VTD_PAGE_TABLE_LEVEL_4               4
#define VTD_PAGE_TABLE_LEVEL_3               3
#define VTD_PAGE_TABLE_LEVEL_2               2
#define VTD_PAGE_TABLE_LEVEL_1               1

// VTD page table flags
#define VTD_PTE_PRESENT                      0x00000001
#define VTD_PTE_READ_WRITE                   0x00000002
#define VTD_PTE_USER_SUPERVISOR              0x00000004
#define VTD_PTE_WRITE_THROUGH                0x00000008
#define VTD_PTE_CACHE_DISABLE                0x00000010
#define VTD_PTE_ACCESSED                     0x00000020
#define VTD_PTE_DIRTY                        0x00000040
#define VTD_PTE_PAGE_SIZE                    0x00000080
#define VTD_PTE_GLOBAL                       0x00000100
#define VTD_PTE_PROTECTION_KEY               0x0000000000000F00

// VTD interrupt remap entry
#define VTD_IRTE_PRESENT                     0x00000001
#define VTD_IRTE_DEST_MODE                   0x00000002
#define VTD_IRTE_REDIR_HINT                  0x00000004
#define VTD_IRTE_TRIGGER_MODE                0x00000008
#define VTD_IRTE_DLM                         0x00000010
#define VTD_IRTE_AVL                         0x00000020
#define VTD_IRTE_RESERVED                    0x00000040
#define VTD_IRTE_SID                         0x000000000000FFFF
#define VTD_IRTE_SQ                          0x0000000000000001
#define VTD_IRTE_SVT                         0x0000000000000002
#define VTD_IRTE_SID_MASK                    0x000000000000FFFF

// VTD 
#define VTD_ERROR_SUCCESS                    0x00000000
#define VTD_ERROR_INVALID_PARAMETER          0x00000001
#define VTD_ERROR_NOT_SUPPORTED              0x00000002
#define VTD_ERROR_OUT_OF_RESOURCES           0x00000003
#define VTD_ERROR_ALREADY_INITIALIZED        0x00000004
#define VTD_ERROR_NOT_INITIALIZED            0x00000005
#define VTD_ERROR_DEVICE_NOT_FOUND           0x00000006
#define VTD_ERROR_DOMAIN_NOT_FOUND           0x00000007
#define VTD_ERROR_INVALID_DOMAIN_ID          0x00000008
#define VTD_ERROR_TABLE_FULL                 0x00000009
#define VTD_ERROR_HARDWARE_FAULT             0x0000000A
#define VTD_ERROR_TIMEOUT                    0x0000000B
#define VTD_ERROR_ACCESS_DENIED              0x0000000C

// VTD Emulation MSRs (Custom ranges for emulation)
#define MSR_VTD_EMULATION_BASE              0x40000000
#define MSR_VTD_STATUS                      0x40000001
#define MSR_VTD_TABLE_BASE                  0x40000002
#define MSR_VTD_DMAR_BASE                   0x40000003
#define MSR_VTD_INTERRUPT_REMAP_BASE        0x40000004
#define MSR_VTD_CAPABILITIES                0x40000005
#define MSR_VTD_DOMAIN_COUNT                0x40000006
#define MSR_VTD_DEVICE_COUNT                0x40000007
#define MSR_VTD_FEATURE_FLAGS               0x40000008
#define MSR_VTD_PERFORMANCE_COUNTER         0x40000009
#define MSR_VTD_ERROR_STATUS                0x4000000A

// VTD Feature Flags
#define VTD_FEATURE_DMA_REMAPPING           0x00000001
#define VTD_FEATURE_INTERRUPT_REMAPPING     0x00000002
#define VTD_FEATURE_COHERENCY               0x00000004
#define VTD_FEATURE_FAULT_LOGGING           0x00000008
#define VTD_FEATURE_PAGE_REQUEST            0x00000010
#define VTD_FEATURE_QUEUED_INVALIDATION     0x00000020
#define VTD_FEATURE_POSTED_INTERRUPTS       0x00000040
#define VTD_FEATURE_SCALABLE_MODE           0x00000080

// VTD Real-time Protection
#define VTD_PROTECTION_ANTI_DEBUG           0x00000001
#define VTD_PROTECTION_ANTI_DUMP            0x00000002
#define VTD_PROTECTION_ANTI_HOOK            0x00000004
#define VTD_PROTECTION_ANTI_VM_DETECT       0x00000008
#define VTD_PROTECTION_MEMORY_ENCRYPTION    0x00000010
#define VTD_PROTECTION_CODE_INTEGRITY       0x00000020

// Anti-debug decay window (in TSC ticks)
#define VTD_ANTI_DEBUG_DECAY_TSC            0x01000000ULL

// CPUID Leaf Extensions for VTD
#define CPUID_VTD_LEAF_BASE                 0x40000000
#define CPUID_VTD_HYPERVISOR_INFO           0x40000000
#define CPUID_VTD_RING2_FEATURES            0x40000001
#define CPUID_VTD_CAPABILITY_INFO           0x40000002
#define CPUID_VTD_DOMAIN_FEATURES           0x40000003
#define CPUID_VTD_DEVICE_FEATURES           0x40000004
#define CPUID_VTD_PERFORMANCE_INFO          0x40000005

#endif // VMX_DEFS_H
