PUBLIC MainAsm
PUBLIC AsmEnableVmxOperation 

PUBLIC GetCs
PUBLIC GetDs
PUBLIC GetEs
PUBLIC GetSs
PUBLIC GetFs
PUBLIC GetGs
PUBLIC GetLdtr
PUBLIC GetTr
PUBLIC Asm_GetIdtBase
PUBLIC Asm_GetIdtLimit
PUBLIC Asm_GetGdtBase  
PUBLIC Asm_GetGdtLimit  
PUBLIC Asm_GetLdtr  
PUBLIC Asm_GetRflags
PUBLIC Asm_VmEntry


EXTERN MainVmexitHandler:PROC
EXTERN VmResumeInstruction:PROC
extern VmGuestEntry:PROC

EXTERN HvReturnStackPointerForVmxoff:PROC
EXTERN HvReturnInstructionPointerForVmxoff:PROC
extern VmxInitalize:PROC
; Saves all general purpose registers to the stack
PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      ; dummy for rsp
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
ENDM

; Loads all general purpose registers from the stack
POPAQ MACRO
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
    add     rsp, 8    ; dummy for rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM

.code _text


MainAsm PROC PUBLIC
push rax
pop  rax
ret
MainAsm ENDP


AsmEnableVmxOperation  PROC PUBLIC

PUSH RAX
XOR  RAX,RAX
MOV  RAX,CR4

OR   RAX,02000h ; SET the 14th bit.
MOV CR4,RAX

POP RAX
ret
AsmEnableVmxOperation ENDP

AsmVmEntryGuest proc
   add rsp, 0100h
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax
	
	popfq	; restore r/eflags

	ret
AsmVmEntryGuest ENDP


AsmVmexitHandler PROC

    push 0
    pushfq

    PUSH R15
    PUSH R14
    PUSH R13
    PUSH R12
    PUSH R11
    PUSH R10
    PUSH R9
    PUSH R8        
    PUSH RDI
    PUSH RSI
    PUSH RBP
    PUSH RBP	; RSP
    PUSH RBX
    PUSH RDX
    PUSH RCX
    PUSH RAX	

	MOV RCX, RSP		; GuestRegs
	SUB	RSP, 28h

	CALL	MainVmexitHandler
	ADD	RSP, 28h	

  	POP RAX
    POP RCX
    POP RDX
    POP RBX
    POP RBP		; RSP
    POP RBP
    POP RSI
    POP RDI 
    POP R8
    POP R9
    POP R10
    POP R11
    POP R12
    POP R13
    POP R14
    POP R15

    popfq

	SUB RSP, 0100h ; to avoid error in future functions
	
    JMP VmResumeInstruction
	
AsmVmexitHandler ENDP


AsmVmxoffHandler PROC
    
    sub rsp, 020h       ; shadow space
    call HvReturnStackPointerForVmxoff
    add rsp, 020h       ; remove for shadow space

    mov [rsp+088h], rax  ; now, rax contains rsp

    sub rsp, 020h       ; shadow space
    call HvReturnInstructionPointerForVmxoff
    add rsp, 020h       ; remove for shadow space

    mov rdx, rsp        ; save current rsp

    mov rbx, [rsp+088h] ; read rsp again

    mov rsp, rbx

    push rax            ; push the return address as we changed the stack, we push
                        ; it to the new stack

    mov rsp, rdx        ; restore previous rsp
                        
    sub rbx,08h         ; we push sth, so we have to add (sub) +8 from previous stack
                        ; also rbx already contains the rsp
    mov [rsp+088h], rbx ; move the new pointer to the current stack

	RestoreState:

	pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		         ; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    popfq

	pop		rsp     ; restore rsp
	ret             ; jump back to where we called Vmcall

AsmVmxoffHandler ENDP

GetCs PROC

	MOV		RAX, CS
	RET

GetCs ENDP

;------------------------------------------------------------------------

GetDs PROC

	MOV		RAX, DS
	RET

GetDs ENDP

;------------------------------------------------------------------------

GetEs PROC

	MOV		RAX, ES
	RET

GetEs ENDP

;------------------------------------------------------------------------

GetSs PROC

	MOV		RAX, SS
	RET

GetSs ENDP

;------------------------------------------------------------------------

GetFs PROC

	MOV		RAX, FS
	RET

GetFs ENDP

;------------------------------------------------------------------------

GetGs PROC

	MOV		RAX, GS
	RET

GetGs ENDP

;------------------------------------------------------------------------

GetLdtr PROC

	SLDT	RAX
	RET

GetLdtr ENDP

;------------------------------------------------------------------------

GetTr PROC

	STR		RAX
	RET

GetTr ENDP

;------------------------------------------------------------------------
Asm_GetIdtBase PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		RAX, QWORD PTR IDTR[2]
	RET

Asm_GetIdtBase ENDP

Asm_GetIdtLimit PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		AX, WORD PTR IDTR[0]

	RET

Asm_GetIdtLimit ENDP

Asm_GetGdtBase PROC
        LOCAL	gdtr[10]:BYTE
        sgdt	gdtr
        mov		rax, qword PTR gdtr[2]
        ret
Asm_GetGdtBase ENDP

Asm_GetGdtLimit PROC
        LOCAL	gdtr[10]:BYTE
        sgdt	gdtr
        mov		ax, WORD PTR gdtr[0]
        ret
Asm_GetGdtLimit ENDP

Asm_GetLdtr PROC
        sldt	rax
        ret
Asm_GetLdtr ENDP

Asm_GetRflags PROC

	PUSHFQ
	POP		RAX
	RET

Asm_GetRflags ENDP

Asm_VmEntry PROC

     RET
Asm_VmEntry ENDP

;------------------------------------------------------------------------

AsmVmxSaveState PROC
	pushfq	; save r/eflag

	push rax
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	sub rsp, 0100h
	; It a x64 FastCall function so the first parameter should go to rcx

	mov rcx, rsp

	call VmxInitalize

	int 3	; we should never reach here as we execute vmlaunch in the above function.
			; if rax is FALSE then it's an indication of error

	jmp AsmVmxRestoreState
		
AsmVmxSaveState ENDP

;------------------------------------------------------------------------

AsmVmxRestoreState PROC
	

	add rsp, 0100h
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax
	
	popfq	; restore r/eflags

	ret
	
AsmVmxRestoreState ENDP

END