; VmxAsm.nasm - Ring-2 
BITS 64
DEFAULT REL

; VMCS 
%define VMCS_GUEST_RSP                         0x0000681C
%define VMCS_GUEST_RIP                         0x0000681E
%define VMCS_GUEST_RSP_HIGH                    0x00006846
%define VMCS_GUEST_RIP_HIGH                    0x00006848

SECTION .text

;  -  VMX 
global AsmVmxOn
global AsmVmClear
global AsmVmPtrLd
global AsmVmRead
global AsmVmWrite
global AsmVmLaunch
global AsmVmResume
global AsmVmxOff
global AsmVmxEnterAndLaunch
global VmExitHandler
global AsmGetCurrentProcessorNumber
global AsmVmFunc
global AsmVmRead64
global AsmVmWrite64
global AsmVmCall
global AsmNestedVmEntry
global AsmNestedVmExit

; 
extern VmExitCDispatcher
extern gVmxContexts
extern gVmxContextSize
extern gGuestRegsOffset
extern Ring2VmExitHandler
extern NestedVmExitHandler

; VMX 

AsmVmxOn:
    vmxon   [rcx]
    jc      .error
    jz      .error
    xor     rax, rax        ; success
    ret
.error:
    mov     rax, 1          ; error
    ret

AsmVmClear:
    vmclear [rcx]
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmVmPtrLd:
    vmptrld [rcx]
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmVmRead:
    vmread  [rdx], rcx
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmVmRead64:
    vmread  [rdx], rcx
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmVmWrite:
    vmwrite rdx, rcx
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmVmWrite64:
    vmwrite rdx, rcx
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmVmLaunch:
    vmlaunch
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmVmResume:
    vmresume
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmVmxOff:
    vmxoff
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmVmFunc:
    vmfunc
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmVmCall:
    vmcall
    jc      .error
    jz      .error
    xor     rax, rax        ; 
    ret
.error:
    mov     rax, 1          ; 
    ret

AsmGetCurrentProcessorNumber:
    ; Simple stub implementation; return 0 for now
    mov     rax, 0          ; temporary 0
    ret

; Ring-2 nested VM Entry
AsmNestedVmEntry:
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
    ; Simplified; real impl should set VMCS fields
    
    ;  Guest RIP  RSP
    mov     rax, VMCS_GUEST_RIP
    vmwrite rcx, rax
    mov     rax, VMCS_GUEST_RSP
    vmwrite rdx, rax
    
    ;  VM Entry
    vmresume
    jc      .error
    jz      .error
    
    ; VM Entry Guest 
    ;  VM Exit
    
.error:
    ; Restore registers on VM entry failure
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
    mov     rax, 1          ; indicate error
    ret

; Ring-2  VM Exit 
AsmNestedVmExit:
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
    call    NestedVmExitHandler
    
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
    
    ; Resume guest
    vmresume
    ret

; VM Exit Handler
VmExitHandler:
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
    
    ; Call C handler with proper parameters
    ; Get VM Exit reason
    mov     rcx, 0x4402     ; VMCS_VM_EXIT_REASON
    vmread  rcx, rcx        ; rcx = exit reason
    mov     rdx, 0          ; rdx = ExitInfo (NULL for now)
    mov     r8, 0           ; r8 = Manager (NULL for now)
    call    Ring2VmExitHandler
    
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
    
    ; Resume guest
    vmresume
    ret

; Helper: set guest RIP/RSP then vmlaunch/vmresume
; rcx = guest_rip, rdx = guest_rsp
AsmVmxEnterAndLaunch:
    push    rbx
    mov     rbx, rcx
    mov     rcx, VMCS_GUEST_RIP
    vmwrite rbx, rcx
    mov     rbx, rdx
    mov     rcx, VMCS_GUEST_RSP
    vmwrite rbx, rcx
    vmlaunch
    jnc     .ok
    vmresume
    jc      .err
.ok:
    pop     rbx
    xor     rax, rax
    ret
.err:
    pop     rbx
    mov     rax, 1
    ret