bits 64
push dword 0x17171717 ; ret (high)
push dword 0x17171717 ; ret (low)
pushfq
; no pushad on x64
push rax
push rbx
push rcx
push rdx
push rsi
push rdi
push rbp
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
push dword 0x23232323 ; align stack
mov rcx, 0x1818181818181818 ; dll path, using fastcall
mov rax, 0x1919191919191919 ; LoadLibrary
call rax
pop rax ; pop dummy stack alignment value
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rbp
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx
pop rax
popfq
ret