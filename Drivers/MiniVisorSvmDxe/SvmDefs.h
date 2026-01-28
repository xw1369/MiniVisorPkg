#ifndef SVM_DEFS_H
#define SVM_DEFS_H

#include <Uefi.h>
#include <Library/BaseLib.h>

// AMD SVM MSR definitions
#define MSR_EFER                              0xC0000080
#define MSR_VM_CR                             0xC0010114
#define MSR_VM_HSAVE_PA                       0xC0010117
#define MSR_SVM_LOCK_KEY                      0xC0010118
#define MSR_HSA                                0xC0010117  // Alias used by code for Host Save Area

// EFER MSR bit fields
#define EFER_SCE                              0x00000001  // System Call Extensions
#define EFER_LME                              0x00000100  // Long Mode Enable
#define EFER_LMA                              0x00000400  // Long Mode Active
#define EFER_NXE                              0x00000800  // No-Execute Enable
#define EFER_SVME                             0x00001000  // Secure Virtual Machine Enable
#define EFER_LMSLE                            0x00002000  // Long Mode Segment Limit Enable
#define EFER_FFXSR                            0x00004000  // Fast FXSAVE/FXRSTOR

// VM_CR MSR bit fields
#define VM_CR_DPD                             0x00000001  // Debug Port Disable
#define VM_CR_R_INIT                          0x00000002  // Intercept INIT
#define VM_CR_DIS_A20M                        0x00000004  // Disable A20 Masking
#define VM_CR_LOCK                            0x00000008  // SVM Lock
#define VM_CR_SVMDIS                          0x00000010  // SVM Disable

// VMCB Control Area offsets
#define VMCB_CONTROL_INTERCEPTS_CR            0x000
#define VMCB_CONTROL_INTERCEPTS_DR            0x004
#define VMCB_CONTROL_INTERCEPTS_EXCEPTION     0x008
#define VMCB_CONTROL_INTERCEPTS_INSTR1        0x00C
#define VMCB_CONTROL_INTERCEPTS_INSTR2        0x010
#define VMCB_CONTROL_INTERCEPTS_INSTR3        0x014
#define VMCB_CONTROL_PAUSE_FILTER_THRESHOLD   0x03C
#define VMCB_CONTROL_PAUSE_FILTER_COUNT       0x03E
#define VMCB_CONTROL_IOPM_BASE_PA             0x040
#define VMCB_CONTROL_MSRPM_BASE_PA            0x048
#define VMCB_CONTROL_TSC_OFFSET               0x050
#define VMCB_CONTROL_ASID                     0x058
#define VMCB_CONTROL_TLB_CONTROL              0x05C
#define VMCB_CONTROL_VINTINTR                 0x060
#define VMCB_CONTROL_INTERRUPT_SHADOW         0x068
#define VMCB_CONTROL_EXITCODE                 0x070
#define VMCB_CONTROL_EXITINFO1                0x078
#define VMCB_CONTROL_EXITINFO2                0x080
#define VMCB_CONTROL_EXITINTINFO              0x088
#define VMCB_CONTROL_NP_ENABLE                0x090
#define VMCB_CONTROL_AVIC_APIC_BAR            0x098
#define VMCB_CONTROL_GHCB_PA                  0x0A0
#define VMCB_CONTROL_EVENTINJ                 0x0A8
#define VMCB_CONTROL_N_CR3                    0x0B0
#define VMCB_CONTROL_LBR_VIRTUALIZATION_ENABLE 0x0B8
#define VMCB_CONTROL_VMCB_CLEAN               0x0C0
#define VMCB_CONTROL_NRIP                     0x0C8
#define VMCB_CONTROL_GUEST_INSTRUCTION_BYTES  0x0D0
#define VMCB_CONTROL_GUEST_INSTRUCTION_LEN    0x0D8
#define VMCB_CONTROL_GUEST_APIC_ID            0x0E0

// VMCB State Save Area offsets
#define VMCB_SAVE_ES                          0x400
#define VMCB_SAVE_CS                          0x410
#define VMCB_SAVE_SS                          0x420
#define VMCB_SAVE_DS                          0x430
#define VMCB_SAVE_FS                          0x440
#define VMCB_SAVE_GS                          0x450
#define VMCB_SAVE_GDTR                        0x460
#define VMCB_SAVE_LDTR                        0x470
#define VMCB_SAVE_IDTR                        0x480
#define VMCB_SAVE_TR                          0x490
#define VMCB_SAVE_CPL                         0x4CB
#define VMCB_SAVE_EFER                        0x4D0
#define VMCB_SAVE_CR4                         0x548
#define VMCB_SAVE_CR3                         0x550
#define VMCB_SAVE_CR0                         0x558
#define VMCB_SAVE_DR7                         0x560
#define VMCB_SAVE_DR6                         0x568
#define VMCB_SAVE_RFLAGS                      0x570
#define VMCB_SAVE_RIP                         0x578
#define VMCB_SAVE_RSP                         0x5D8
#define VMCB_SAVE_RAX                         0x5F8
#define VMCB_SAVE_STAR                        0x600
#define VMCB_SAVE_LSTAR                       0x608
#define VMCB_SAVE_CSTAR                       0x610
#define VMCB_SAVE_SFMASK                      0x618
#define VMCB_SAVE_KERNEL_GS_BASE              0x620
#define VMCB_SAVE_SYSENTER_CS                 0x628
#define VMCB_SAVE_SYSENTER_ESP                0x630
#define VMCB_SAVE_SYSENTER_EIP                0x638
#define VMCB_SAVE_CR2                         0x640
#define VMCB_SAVE_G_PAT                       0x668
#define VMCB_SAVE_DBGCTL                      0x670
#define VMCB_SAVE_BR_FROM                     0x678
#define VMCB_SAVE_BR_TO                       0x680
#define VMCB_SAVE_LAST_EXCP_FROM              0x688
#define VMCB_SAVE_LAST_EXCP_TO                0x690

// SVM Exit codes
#define SVM_EXIT_CR0_READ                     0x000
#define SVM_EXIT_CR1_READ                     0x001
#define SVM_EXIT_CR2_READ                     0x002
#define SVM_EXIT_CR3_READ                     0x003
#define SVM_EXIT_CR4_READ                     0x004
#define SVM_EXIT_CR5_READ                     0x005
#define SVM_EXIT_CR6_READ                     0x006
#define SVM_EXIT_CR7_READ                     0x007
#define SVM_EXIT_CR8_READ                     0x008
#define SVM_EXIT_CR9_READ                     0x009
#define SVM_EXIT_CR10_READ                    0x00A
#define SVM_EXIT_CR11_READ                    0x00B
#define SVM_EXIT_CR12_READ                    0x00C
#define SVM_EXIT_CR13_READ                    0x00D
#define SVM_EXIT_CR14_READ                    0x00E
#define SVM_EXIT_CR15_READ                    0x00F
#define SVM_EXIT_CR0_WRITE                    0x010
#define SVM_EXIT_CR1_WRITE                    0x011
#define SVM_EXIT_CR2_WRITE                    0x012
#define SVM_EXIT_CR3_WRITE                    0x013
#define SVM_EXIT_CR4_WRITE                    0x014
#define SVM_EXIT_CR5_WRITE                    0x015
#define SVM_EXIT_CR6_WRITE                    0x016
#define SVM_EXIT_CR7_WRITE                    0x017
#define SVM_EXIT_CR8_WRITE                    0x018
#define SVM_EXIT_CR9_WRITE                    0x019
#define SVM_EXIT_CR10_WRITE                   0x01A
#define SVM_EXIT_CR11_WRITE                   0x01B
#define SVM_EXIT_CR12_WRITE                   0x01C
#define SVM_EXIT_CR13_WRITE                   0x01D
#define SVM_EXIT_CR14_WRITE                   0x01E
#define SVM_EXIT_CR15_WRITE                   0x01F
#define SVM_EXIT_DR0_READ                     0x020
#define SVM_EXIT_DR1_READ                     0x021
#define SVM_EXIT_DR2_READ                     0x022
#define SVM_EXIT_DR3_READ                     0x023
#define SVM_EXIT_DR4_READ                     0x024
#define SVM_EXIT_DR5_READ                     0x025
#define SVM_EXIT_DR6_READ                     0x026
#define SVM_EXIT_DR7_READ                     0x027
#define SVM_EXIT_DR8_READ                     0x028
#define SVM_EXIT_DR9_READ                     0x029
#define SVM_EXIT_DR10_READ                    0x02A
#define SVM_EXIT_DR11_READ                    0x02B
#define SVM_EXIT_DR12_READ                    0x02C
#define SVM_EXIT_DR13_READ                    0x02D
#define SVM_EXIT_DR14_READ                    0x02E
#define SVM_EXIT_DR15_READ                    0x02F
#define SVM_EXIT_DR0_WRITE                    0x030
#define SVM_EXIT_DR1_WRITE                    0x031
#define SVM_EXIT_DR2_WRITE                    0x032
#define SVM_EXIT_DR3_WRITE                    0x033
#define SVM_EXIT_DR4_WRITE                    0x034
#define SVM_EXIT_DR5_WRITE                    0x035
#define SVM_EXIT_DR6_WRITE                    0x036
#define SVM_EXIT_DR7_WRITE                    0x037
#define SVM_EXIT_DR8_WRITE                    0x038
#define SVM_EXIT_DR9_WRITE                    0x039
#define SVM_EXIT_DR10_WRITE                   0x03A
#define SVM_EXIT_DR11_WRITE                   0x03B
#define SVM_EXIT_DR12_WRITE                   0x03C
#define SVM_EXIT_DR13_WRITE                   0x03D
#define SVM_EXIT_DR14_WRITE                   0x03E
#define SVM_EXIT_DR15_WRITE                   0x03F
#define SVM_EXIT_EXCP_BASE                    0x040
#define SVM_EXIT_INTR                         0x060
#define SVM_EXIT_NMI                          0x061
#define SVM_EXIT_SMI                          0x062
#define SVM_EXIT_INIT                         0x063
#define SVM_EXIT_VINTR                        0x064
#define SVM_EXIT_CR0_SEL_WRITE                0x065
#define SVM_EXIT_IDTR_READ                    0x066
#define SVM_EXIT_GDTR_READ                    0x067
#define SVM_EXIT_LDTR_READ                    0x068
#define SVM_EXIT_TR_READ                      0x069
#define SVM_EXIT_IDTR_WRITE                   0x06A
#define SVM_EXIT_GDTR_WRITE                   0x06B
#define SVM_EXIT_LDTR_WRITE                   0x06C
#define SVM_EXIT_TR_WRITE                     0x06D
#define SVM_EXIT_RDTSC                        0x06E
#define SVM_EXIT_RDPMC                        0x06F
#define SVM_EXIT_PUSHF                        0x070
#define SVM_EXIT_POPF                         0x071
#define SVM_EXIT_CPUID                        0x072
#define SVM_EXIT_RSM                          0x073
#define SVM_EXIT_IRET                         0x074
#define SVM_EXIT_SWINT                        0x075
#define SVM_EXIT_INVD                         0x076
#define SVM_EXIT_PAUSE                        0x077
#define SVM_EXIT_HLT                          0x078
#define SVM_EXIT_INVLPG                       0x079
#define SVM_EXIT_INVLPGA                      0x07A
#define SVM_EXIT_IOIO                         0x07B
#define SVM_EXIT_MSR                          0x07C
#define SVM_EXIT_TASK_SWITCH                  0x07D
#define SVM_EXIT_FERR_FREEZE                  0x07E
#define SVM_EXIT_SHUTDOWN                     0x07F
#define SVM_EXIT_VMRUN                        0x080
#define SVM_EXIT_VMMCALL                      0x081
#define SVM_EXIT_VMLOAD                       0x082
#define SVM_EXIT_VMSAVE                       0x083
#define SVM_EXIT_STGI                         0x084
#define SVM_EXIT_CLGI                         0x085
#define SVM_EXIT_SKINIT                       0x086
#define SVM_EXIT_RDTSCP                       0x087
#define SVM_EXIT_ICEBP                        0x088
#define SVM_EXIT_WBINVD                       0x089
#define SVM_EXIT_MONITOR                      0x08A
#define SVM_EXIT_MWAIT                        0x08B
#define SVM_EXIT_MWAIT_CONDITIONAL            0x08C
#define SVM_EXIT_XSETBV                       0x08D
#define SVM_EXIT_NPF                          0x400
#define SVM_EXIT_AVIC_INCOMPLETE_IPI          0x401
#define SVM_EXIT_AVIC_UNACCELERATED_ACCESS    0x402
#define SVM_EXIT_VMGEXIT                      0x403

// SVM Intercept bits for Control Register reads
#define SVM_INTERCEPT_CR0_READ                0x00000001
#define SVM_INTERCEPT_CR3_READ                0x00000008
#define SVM_INTERCEPT_CR4_READ                0x00000010
#define SVM_INTERCEPT_CR8_READ                0x00000100

// SVM Intercept bits for Control Register writes
#define SVM_INTERCEPT_CR0_WRITE               0x00010000
#define SVM_INTERCEPT_CR3_WRITE               0x00080000
#define SVM_INTERCEPT_CR4_WRITE               0x00100000
#define SVM_INTERCEPT_CR8_WRITE               0x01000000

// SVM Intercept bits for Debug Register reads/writes
#define SVM_INTERCEPT_DR0_READ                0x00000001
#define SVM_INTERCEPT_DR1_READ                0x00000002
#define SVM_INTERCEPT_DR2_READ                0x00000004
#define SVM_INTERCEPT_DR3_READ                0x00000008
#define SVM_INTERCEPT_DR4_READ                0x00000010
#define SVM_INTERCEPT_DR5_READ                0x00000020
#define SVM_INTERCEPT_DR6_READ                0x00000040
#define SVM_INTERCEPT_DR7_READ                0x00000080
#define SVM_INTERCEPT_DR0_WRITE               0x00000100
#define SVM_INTERCEPT_DR1_WRITE               0x00000200
#define SVM_INTERCEPT_DR2_WRITE               0x00000400
#define SVM_INTERCEPT_DR3_WRITE               0x00000800
#define SVM_INTERCEPT_DR4_WRITE               0x00001000
#define SVM_INTERCEPT_DR5_WRITE               0x00002000
#define SVM_INTERCEPT_DR6_WRITE               0x00004000
#define SVM_INTERCEPT_DR7_WRITE               0x00008000

// SVM Intercept bits for exceptions
#define SVM_INTERCEPT_EXCEPTION_DE            0x00000001
#define SVM_INTERCEPT_EXCEPTION_DB            0x00000002
#define SVM_INTERCEPT_EXCEPTION_NMI           0x00000004
#define SVM_INTERCEPT_EXCEPTION_BP            0x00000008
#define SVM_INTERCEPT_EXCEPTION_OF            0x00000010
#define SVM_INTERCEPT_EXCEPTION_BR            0x00000020
#define SVM_INTERCEPT_EXCEPTION_UD            0x00000040
#define SVM_INTERCEPT_EXCEPTION_NM            0x00000080
#define SVM_INTERCEPT_EXCEPTION_DF            0x00000100
#define SVM_INTERCEPT_EXCEPTION_TS            0x00000400
#define SVM_INTERCEPT_EXCEPTION_NP            0x00000800
#define SVM_INTERCEPT_EXCEPTION_SS            0x00001000
#define SVM_INTERCEPT_EXCEPTION_GP            0x00002000
#define SVM_INTERCEPT_EXCEPTION_PF            0x00004000
#define SVM_INTERCEPT_EXCEPTION_MF            0x00008000
#define SVM_INTERCEPT_EXCEPTION_AC            0x00010000
#define SVM_INTERCEPT_EXCEPTION_MC            0x00020000
#define SVM_INTERCEPT_EXCEPTION_XF            0x00040000

// SVM Intercept bits for instructions (Set 1)
#define SVM_INTERCEPT_INTR                    0x00000001
#define SVM_INTERCEPT_NMI                     0x00000002
#define SVM_INTERCEPT_SMI                     0x00000004
#define SVM_INTERCEPT_INIT                    0x00000008
#define SVM_INTERCEPT_VINTR                   0x00000010
#define SVM_INTERCEPT_CR0_SEL_WRITE           0x00000020
#define SVM_INTERCEPT_IDTR_READ               0x00000040
#define SVM_INTERCEPT_GDTR_READ               0x00000080
#define SVM_INTERCEPT_LDTR_READ               0x00000100
#define SVM_INTERCEPT_TR_READ                 0x00000200
#define SVM_INTERCEPT_IDTR_WRITE              0x00000400
#define SVM_INTERCEPT_GDTR_WRITE              0x00000800
#define SVM_INTERCEPT_LDTR_WRITE              0x00001000
#define SVM_INTERCEPT_TR_WRITE                0x00002000
#define SVM_INTERCEPT_RDTSC                   0x00004000
#define SVM_INTERCEPT_RDPMC                   0x00008000
#define SVM_INTERCEPT_PUSHF                   0x00010000
#define SVM_INTERCEPT_POPF                    0x00020000
#define SVM_INTERCEPT_CPUID                   0x00040000
#define SVM_INTERCEPT_RSM                     0x00080000
#define SVM_INTERCEPT_IRET                    0x00100000
#define SVM_INTERCEPT_INTn                    0x00200000
#define SVM_INTERCEPT_INVD                    0x00400000
#define SVM_INTERCEPT_PAUSE                   0x00800000
#define SVM_INTERCEPT_HLT                     0x01000000
#define SVM_INTERCEPT_INVLPG                  0x02000000
#define SVM_INTERCEPT_INVLPGA                 0x04000000
#define SVM_INTERCEPT_IOIO_PROT               0x08000000
#define SVM_INTERCEPT_MSR_PROT                0x10000000
#define SVM_INTERCEPT_TASK_SWITCHES           0x20000000
#define SVM_INTERCEPT_FERR_FREEZE             0x40000000
#define SVM_INTERCEPT_SHUTDOWN                0x80000000

// SVM Intercept bits for instructions (Set 2)
#define SVM_INTERCEPT_VMRUN                   0x00000001
#define SVM_INTERCEPT_VMMCALL                 0x00000002
#define SVM_INTERCEPT_VMLOAD                  0x00000004
#define SVM_INTERCEPT_VMSAVE                  0x00000008
#define SVM_INTERCEPT_STGI                    0x00000010
#define SVM_INTERCEPT_CLGI                    0x00000020
#define SVM_INTERCEPT_SKINIT                  0x00000040
#define SVM_INTERCEPT_RDTSCP                  0x00000080
#define SVM_INTERCEPT_ICEBP                   0x00000100
#define SVM_INTERCEPT_WBINVD                  0x00000200
#define SVM_INTERCEPT_MONITOR                 0x00000400
#define SVM_INTERCEPT_MWAIT                   0x00000800
#define SVM_INTERCEPT_MWAIT_CONDITIONAL       0x00001000
#define SVM_INTERCEPT_XSETBV                  0x00002000

// NPT (Nested Page Table) constants
#define NPT_PML4E_PRESENT                     0x00000001
#define NPT_PML4E_WRITE                       0x00000002
#define NPT_PML4E_USER                        0x00000004
#define NPT_PML4E_ACCESSED                    0x00000020
#define NPT_PML4E_DIRTY                       0x00000040
#define NPT_PML4E_PAGE_SIZE                   0x00000080

// NPT page fault error bits (for ExitInfo1 interpretation)
// Bit definitions are based on AMD APM: W=0x2, X=0x4, U=0x8 where applicable
#ifndef NPT_ERROR_WRITE
#define NPT_ERROR_WRITE                        0x00000002
#endif
#ifndef NPT_ERROR_EXECUTE
#define NPT_ERROR_EXECUTE                      0x00000004
#endif
#ifndef NPT_ERROR_USER
#define NPT_ERROR_USER                         0x00000008
#endif

// VMCB Clean Bits
// Base clean-bit macros
#ifndef VMCB_CLEAN_INTERCEPTS
#define VMCB_CLEAN_INTERCEPTS                  0x00000001
#endif
#ifndef VMCB_CLEAN_IOPM
#define VMCB_CLEAN_IOPM                        0x00000002
#endif
#ifndef VMCB_CLEAN_ASID
#define VMCB_CLEAN_ASID                        0x00000004
#endif
#ifndef VMCB_CLEAN_TPR
#define VMCB_CLEAN_TPR                         0x00000008
#endif
#ifndef VMCB_CLEAN_NP
#define VMCB_CLEAN_NP                          0x00000010
#endif
#ifndef VMCB_CLEAN_CRX
#define VMCB_CLEAN_CRX                         0x00000020
#endif
#ifndef VMCB_CLEAN_DRX
#define VMCB_CLEAN_DRX                         0x00000040
#endif
#ifndef VMCB_CLEAN_DT
#define VMCB_CLEAN_DT                          0x00000080
#endif
#ifndef VMCB_CLEAN_SEG
#define VMCB_CLEAN_SEG                         0x00000100
#endif
#ifndef VMCB_CLEAN_CR2
#define VMCB_CLEAN_CR2                         0x00000200
#endif
#ifndef VMCB_CLEAN_LBR
#define VMCB_CLEAN_LBR                         0x00000400
#endif
#ifndef VMCB_CLEAN_AVIC
#define VMCB_CLEAN_AVIC                        0x00000800
#endif

// Canonical clean-bit names used in this codebase (aliases)
#define VMCB_CLEAN_INTERCEPT_VECTOR            VMCB_CLEAN_INTERCEPTS
#define VMCB_CLEAN_CONTROL                     VMCB_CLEAN_CRX
#define VMCB_CLEAN_DR                          VMCB_CLEAN_DRX

// VMCB sizes
#define VMCB_SIZE                             0x1000
#define VMCB_CONTROL_AREA_SIZE                0x400
#define VMCB_STATE_SAVE_AREA_SIZE             0x298

// Ring-2 SVM state
#define RING2_SVM_STATE_DISABLED              0
#define RING2_SVM_STATE_ENABLED               1
#define RING2_SVM_STATE_NESTED_ENABLED        2

#define NESTED_SVM_MAX_VMCB_COUNT             16
#define NESTED_SVM_VMCB_SIZE                  4096
#define NESTED_SVM_HSA_SIZE                   4096

// Ring-2 privilege levels (same as VMX)
#define RING2_PRIVILEGE_LEVEL_0               0
#define RING2_PRIVILEGE_LEVEL_1               1
#define RING2_PRIVILEGE_LEVEL_2               2
#define RING2_PRIVILEGE_LEVEL_3               3

// ASID (Address Space Identifier) constants
#define SVM_ASID_MIN                          1
#define SVM_ASID_MAX                          0xFFFF

// SVM Feature flags
#define SVM_FEATURE_NPT                       0x00000001
#define SVM_FEATURE_LBR_VIRT                  0x00000002
#define SVM_FEATURE_SVM_LOCK                  0x00000004
#define SVM_FEATURE_NRIP_SAVE                 0x00000008
#define SVM_FEATURE_TSC_RATE                  0x00000010
#define SVM_FEATURE_VMCB_CLEAN                0x00000020
#define SVM_FEATURE_DECODE_ASSISTS            0x00000080
#define SVM_FEATURE_PAUSE_FILTER              0x00000400
#define SVM_FEATURE_PAUSE_THRESH              0x00001000
#define SVM_FEATURE_AVIC                      0x00002000
#define SVM_FEATURE_VMSAVE_VMLOAD             0x00008000
#define SVM_FEATURE_VGIF                      0x00010000
#define SVM_FEATURE_GMET                      0x00020000

// CPUID function for SVM
#define CPUID_SVM_LEAF                        0x8000000A

// CPUID SVM feature bits
#define CPUID_SVM_NESTED_PAGING               0x00000001
#define CPUID_SVM_LBR_VIRT                    0x00000002
#define CPUID_SVM_LOCK                        0x00000004
#define CPUID_SVM_NRIP_SAVE                   0x00000008
#define CPUID_SVM_TSC_RATE_MSR                0x00000010
#define CPUID_SVM_VMCB_CLEAN                  0x00000020
#define CPUID_SVM_FLUSH_BY_ASID               0x00000040
#define CPUID_SVM_DECODE_ASSISTS              0x00000080
#define CPUID_SVM_PAUSE_FILTER                0x00000400
#define CPUID_SVM_PAUSE_THRESH                0x00001000
#define CPUID_SVM_AVIC                        0x00002000
#define CPUID_SVM_VMSAVE_VMLOAD               0x00008000
#define CPUID_SVM_VGIF                        0x00010000
#define CPUID_SVM_GMET                        0x00020000

// Control Register bit definitions used by security checks
#ifndef CR0_PE
#define CR0_PE                                 0x00000001
#endif
#ifndef CR0_PG
#define CR0_PG                                 0x80000000
#endif
#ifndef CR4_PAE
#define CR4_PAE                                0x00000020
#endif

#endif // SVM_DEFS_H
