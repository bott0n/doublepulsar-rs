SpoofSynthetic proto

.data

Config STRUCT
    RtlUserThreadStartAddr       DQ 1
    RtlUserThreadStartFrameSize  DQ 1

    BaseThreadInitThunkAddr      DQ 1
    BaseThreadInitThunkFrameSize DQ 1

    FirstFrame                   DQ 1
    SecondFrame                  DQ 1
    JmpRbxGadget                 DQ 1
    AddRspXGadget                DQ 1

    FirstFrameSize               DQ 1
    SecondFrameSize              DQ 1
    JmpRbxGadgetFrameSize        DQ 1
    AddRspXGadgetFrameSize       DQ 1

    RbpOffset                    DQ 1

    SpooFunction                 DQ 1
    ReturnAddress                DQ 1

    IsSyscall                    DD 0
    Ssn                          DD 0

    NArgs                        DQ 1
    Arg01                        DQ 1
    Arg02                        DQ 1
    Arg03                        DQ 1
    Arg04                        DQ 1
    Arg05                        DQ 1
    Arg06                        DQ 1
    Arg07                        DQ 1
    Arg08                        DQ 1
    Arg09                        DQ 1
    Arg10                        DQ 1
    Arg11                        DQ 1
Config ENDS

.code

SpoofSynthetic PROC
    push rbp
    push rbx
    push r12
    push r13
    push r15

    sub rsp, 210h
    mov rbp, rsp

    lea rax, RestoreSynthetic
    push rax
    lea rbx, [rsp]

    xor rax, rax
    push rax

    sub rsp, [rcx].Config.RtlUserThreadStartFrameSize
    push [rcx].Config.RtlUserThreadStartAddr
    add QWORD PTR [rsp], 21h

    sub rsp, [rcx].Config.BaseThreadInitThunkFrameSize
    push [rcx].Config.BaseThreadInitThunkAddr
    add QWORD PTR [rsp], 14h

    mov rax, rsp

    push [rcx].Config.FirstFrame
    sub rax, [rcx].Config.FirstFrameSize

    sub rsp, [rcx].Config.SecondFrameSize
    mov r10, [rcx].Config.RbpOffset
    mov [rsp + r10], rax

    push [rcx].Config.SecondFrame

    sub rsp, [rcx].Config.JmpRbxGadgetFrameSize
    push [rcx].Config.JmpRbxGadget

    sub rsp, [rcx].Config.AddRspXGadgetFrameSize
    push [rcx].Config.AddRspXGadget

    mov r11, [rcx].Config.SpooFunction
    jmp ParametersSynthetic
SpoofSynthetic ENDP

ParametersSynthetic PROC
    mov r12, rcx
    mov rax, [r12].Config.NArgs

    cmp rax, 1
    jb skip_1
    mov rcx, [r12].Config.Arg01

skip_1:
    cmp rax, 2
    jb skip_2
    mov rdx, [r12].Config.Arg02

skip_2:
    cmp rax, 3
    jb skip_3
    mov r8, [r12].Config.Arg03

skip_3:
    cmp rax, 4
    jb skip_4
    mov r9, [r12].Config.Arg04

skip_4:
    lea r13, [rsp]

    cmp rax, 5
    jb skip_5
    mov r10, [r12].Config.Arg05
    mov [r13 + 28h], r10

skip_5:
    cmp rax, 6
    jb skip_6
    mov r10, [r12].Config.Arg06
    mov [r13 + 30h], r10

skip_6:
    cmp rax, 7
    jb skip_7
    mov r10, [r12].Config.Arg07
    mov [r13 + 38h], r10

skip_7:
    cmp rax, 8
    jb skip_8
    mov r10, [r12].Config.Arg08
    mov [r13 + 40h], r10

skip_8:
    cmp rax, 9
    jb skip_9
    mov r10, [r12].Config.Arg09
    mov [r13 + 48h], r10

skip_9:
    cmp rax, 10
    jb skip_10
    mov r10, [r12].Config.Arg10
    mov [r13 + 50h], r10

skip_10:
    cmp rax, 11
    jb skip_11
    mov r10, [r12].Config.Arg11
    mov [r13 + 58h], r10

skip_11:
    cmp [r12].Config.IsSyscall, 1
    je ExecuteSyscallSynthetic

    jmp ExecuteSynthetic
ParametersSynthetic ENDP

RestoreSynthetic PROC
    mov rsp, rbp
    add rsp, 210h
    pop r15
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
RestoreSynthetic ENDP

ExecuteSynthetic PROC
    jmp QWORD PTR r11
ExecuteSynthetic ENDP

ExecuteSyscallSynthetic PROC
    mov r10, rcx
    mov eax, [r12].Config.Ssn
    jmp QWORD PTR r11
ExecuteSyscallSynthetic ENDP

END
