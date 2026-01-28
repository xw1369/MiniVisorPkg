; SvmAsm.nasm - Ring-2 SVM Assembly functions
BITS 64
DEFAULT REL

; VMCB offsets for SVM
%define VMCB_SAVE_RAX                         0x5F8
%define VMCB_SAVE_RSP                         0x5D8
%define VMCB_SAVE_RIP                         0x578
%define VMCB_SAVE_RFLAGS                      0x570

; MSR definitions
%define MSR_EFER                              0xC0000080
%define MSR_VM_CR                             0xC0010114
%define MSR_VM_HSAVE_PA                       0xC0010117

; EFER bits
%define EFER_SVME                             0x1000

SECTION .text

; Export SVM assembly functions
global AsmEnableSvm
global AsmDisableSvm
global AsmVmrun
global AsmVmsave
global AsmVmload
global AsmVmmcall
global AsmStgi
global AsmClgi
global AsmSvmEnterAndLaunch
global SvmExitHandler
global AsmGetCurrentProcessorNumber
global AsmNestedSvmEntry
global AsmNestedSvmExit
global AsmReadMsr
global AsmWriteMsr

; External C functions
extern SvmExitCDispatcher
extern gSvmContexts
extern gSvmContextSize
extern gGuestRegsOffset
; Use the nested exit handler defined in C
extern NestedSvmExitHandler
extern NestedSvmExitHandler

; SVM Core Functions

AsmEnableSvm:
    ; Read EFER MSR
    mov     ecx, MSR_EFER
    rdmsr
    ; Set SVME bit (bit 12)
    or      eax, EFER_SVME
    ; Write back EFER MSR
    wrmsr
    xor     rax, rax        ; success
    ret

AsmDisableSvm:
    ; Read EFER MSR
    mov     ecx, MSR_EFER
    rdmsr
    ; Clear SVME bit (bit 12)
    and     eax, ~EFER_SVME
    ; Write back EFER MSR
    wrmsr
    xor     rax, rax        ; success
    ret

AsmVmrun:
    ; Input: rcx = VMCB physical address
    ; Save host state in RAX (required by SVM)
    mov     rax, rcx
    ; Execute VMRUN (RAX is implicit)
    vmrun
    ; If we reach here, VM entry failed or VM exited
    xor     rax, rax        ; success (VM exit)
    ret

AsmVmsave:
    ; Input: rcx = VMCB physical address
    mov     rax, rcx
    ; VMSAVE uses implicit RAX
    vmsave
    jc      .error
    xor     rax, rax        ; success
    ret
.error:
    mov     rax, 1          ; error
    ret

AsmVmload:
    ; Input: rcx = VMCB physical address
    mov     rax, rcx
    ; VMLOAD uses implicit RAX
    vmload
    jc      .error
    xor     rax, rax        ; success
    ret
.error:
    mov     rax, 1          ; error
    ret

AsmVmmcall:
    vmmcall
    xor     rax, rax        ; success
    ret

AsmStgi:
    stgi
    xor     rax, rax        ; success
    ret

AsmClgi:
    clgi
    xor     rax, rax        ; success
    ret

AsmGetCurrentProcessorNumber:
    ; Simple stub implementation; return 0 for now
    mov     rax, 0          ; temporary return 0
    ret

; MSR read/write functions
AsmReadMsr:
    ; Input: rcx = MSR number
    ; Output: rax = MSR value (64-bit)
    mov     r8, rcx         ; Save MSR number
    mov     ecx, r8d        ; MSR number to ECX
    rdmsr                   ; Read MSR (EDX:EAX)
    shl     rdx, 32         ; Shift high part to upper 32 bits
    or      rax, rdx        ; Combine high and low parts
    ret

AsmWriteMsr:
    ; Input: rcx = MSR number, rdx = MSR value (64-bit)
    mov     r8, rdx         ; Save MSR value
    mov     ecx, ecx        ; MSR number to ECX
    mov     eax, r8d        ; Low 32 bits to EAX
    shr     r8, 32          ; Shift high part down
    mov     edx, r8d        ; High 32 bits to EDX
    wrmsr                   ; Write MSR
    xor     rax, rax        ; Return success
    ret

; Control register access functions
; Remove CR read/write helpers to avoid duplicate symbol conflicts with BaseLib

; Ring-2 nested SVM Entry
AsmNestedSvmEntry:
    ; Save general purpose registers
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
    
    ; Set stack frame
    mov     rbp, rsp
    
    ; Input: rcx = Guest RIP, rdx = Guest RSP, r8 = Guest RFLAGS
    ; Load VMCB address from global variable
    ; Simplified implementation - real version should properly set VMCB fields
    
    ; Set guest state in VMCB
    ; This is a simplified version - real implementation needs proper VMCB setup
    mov     rax, rcx        ; Guest RIP
    ; Store guest RIP in VMCB
    ; mov     [vmcb + VMCB_SAVE_RIP], rax
    
    mov     rax, rdx        ; Guest RSP
    ; Store guest RSP in VMCB
    ; mov     [vmcb + VMCB_SAVE_RSP], rax
    
    ; Execute nested VM entry
    ; mov     rax, vmcb_physical_address
    ; vmrun   rax
    
    ; For now, just return success
    xor     rax, rax
    
    ; Restore registers
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    ret

; Ring-2 nested SVM Exit handler
AsmNestedSvmExit:
    ; Save registers
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
    
    ; Set stack frame
    mov     rbp, rsp
    
    ; Call C handler
    mov     rcx, rsp        ; pass registers pointer
    call    NestedSvmExitHandler
    
    ; Restore registers
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    
    ; Continue guest execution
    ; vmrun instruction would be here in real implementation
    ret

; SVM Exit Handler
SvmExitHandler:
    ; Save all general purpose registers
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
    
    ; Set stack frame
    mov     rbp, rsp
    
    ; SVM automatically provides exit information in VMCB
    ; Exit code is in VMCB offset 0x70
    ; For now, we'll call the C handler with general parameters
    
    ; Get exit code from VMCB (simplified - should read from actual VMCB)
    xor     rcx, rcx        ; Exit code (placeholder)
    xor     rdx, rdx        ; Exit info (placeholder)
    mov     r8, rsp         ; Context (registers)
    
    ; Call C handler
    call    NestedSvmExitHandler
    
    ; Restore registers
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    
    ; Continue guest execution
    ; vmrun instruction should be executed here to resume guest
    ret

; Helper: set guest state then vmrun
; rcx = guest_rip, rdx = guest_rsp, r8 = vmcb_physical_address
AsmSvmEnterAndLaunch:
    push    rbx
    push    r9
    
    mov     rbx, r8         ; VMCB physical address
    
    ; Set guest RIP in VMCB
    ; mov     [rbx + VMCB_SAVE_RIP], rcx
    
    ; Set guest RSP in VMCB
    ; mov     [rbx + VMCB_SAVE_RSP], rdx
    
    ; Execute VMRUN
    mov     rax, rbx        ; VMCB physical address must be in RAX
    ; VMRUN uses implicit RAX
    vmrun
    
    ; If we return here, either VM entry failed or guest exited
    pop     r9
    pop     rbx
    xor     rax, rax        ; Return success
    ret

; Utility functions for SVM debugging and diagnostics

; Read VM_CR MSR
global AsmReadVmCr
AsmReadVmCr:
    mov     ecx, MSR_VM_CR
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    ret

; Write VM_CR MSR
global AsmWriteVmCr
AsmWriteVmCr:
    ; Input: rcx = value to write
    mov     r8, rcx
    mov     ecx, MSR_VM_CR
    mov     eax, r8d
    shr     r8, 32
    mov     edx, r8d
    wrmsr
    xor     rax, rax
    ret

; Read VM_HSAVE_PA MSR
global AsmReadVmHsavePa
AsmReadVmHsavePa:
    mov     ecx, MSR_VM_HSAVE_PA
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    ret

; Write VM_HSAVE_PA MSR
global AsmWriteVmHsavePa
AsmWriteVmHsavePa:
    ; Input: rcx = physical address of host save area
    mov     r8, rcx
    mov     ecx, MSR_VM_HSAVE_PA
    mov     eax, r8d
    shr     r8, 32
    mov     edx, r8d
    wrmsr
    xor     rax, rax
    ret

; Invalidate TLB entries for specific ASID
global AsmInvalidateTlbByAsid
AsmInvalidateTlbByAsid:
    ; Input: rcx = ASID
    ; This is typically handled by hardware, but we can trigger
    ; a TLB flush by writing to certain control registers
    ; For now, just do a complete TLB flush
    mov     rax, cr3
    mov     cr3, rax
    xor     rax, rax
    ret

; Check if we're running in a VM
global AsmCheckIfInVm
AsmCheckIfInVm:
    ; Try to execute a privileged SVM instruction
    ; If we're in a VM, it might be intercepted
    push    rbx
    push    rcx
    push    rdx
    
    ; Try to read VM_CR MSR
    mov     ecx, MSR_VM_CR
    rdmsr
    ; If this succeeds without exception, we might be in host mode
    ; This is a simplified check
    
    pop     rdx
    pop     rcx
    pop     rbx
    xor     rax, rax        ; Return 0 (not in VM)
    ret
