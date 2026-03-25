.global context_switch

context_switch:
    # Save current context
    # push registers that context_switch is expected to preserve (callee-saved)
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    # Save current stack pointer
    # RCX is the first argument (old_rsp) in Win64 calling convention
    mov %rsp, (%rcx)

    # Restore new context
    # RDX is the second argument (next_rsp) in Win64 calling convention
    mov %rdx, %rsp

    # pop registers in reverse order
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx

    ret
