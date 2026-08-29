.CODE

EXTERN HookTable:QWORD
PUBLIC HookThunk

ALIGN 16
HookThunk PROC

mov r11, rcx                  ; <-- add: preserve the real first argument
xor rax, rax

LoopStart:

cmp qword ptr [rsp], rcx
jne LoopEnd
inc rax
add rsp, 8
jmp LoopStart

LoopEnd:

lea rcx, HookTable
mov rax, [rcx + rax * 8]
mov rcx, [rsp - 8]

mov rcx, r11                  ; <-- replace: was mov rcx, [rsp - 8]
jmp rax

HookThunk ENDP

PUBLIC NtAllocateVirtualMemoryThunk
EXTERN NtAllocateVirtualMemorySsn:DWORD

NtAllocateVirtualMemoryThunk PROC

mov r10, rcx
mov eax, NtAllocateVirtualMemorySsn
syscall
ret

NtAllocateVirtualMemoryThunk ENDP

END