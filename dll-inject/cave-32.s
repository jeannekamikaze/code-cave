bits 32
push dword 0x17171717 ; ret
pushfd
pushad
push dword 0x18181818 ; dll path
mov eax, 0x19191919 ; LoadLibrary
call eax
popad
popfd
ret