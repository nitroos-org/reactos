
#pragma once

struct _SEH$$_EXCEPTION_RECORD
{
    unsigned long ExceptionCode;
    unsigned long ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    void* ExceptionAddress;
    unsigned long NumberParameters;
    unsigned long long ExceptionInformation[15];
};

struct _SEH$$_EXCEPTION_POINTERS
{
    struct _SEH$$_EXCEPTION_RECORD *ExceptionRecord;
    struct _CONTEXT *ContextRecord;
};

/* The compiler plugin emits the funclet trampoline after it knows the largest
 * outgoing argument area in this translation unit. The trampoline preserves
 * both integer and XMM nonvolatile registers when calling a funclet. */
typedef void (*__seh2_finally_function)(int, void*);

struct __seh2_scope
{
    __seh2_finally_function Handler;
    void* Frame;
    void* Stack;
};

/* GCC invokes this when a return, goto or break leaves a try/finally scope. */
static __inline__ __attribute__((always_inline))
void __seh2_scope_exit(volatile struct __seh2_scope* Scope)
{
    __seh2_finally_function Handler = Scope->Handler;
    if (Handler)
    {
        Scope->Handler = 0;
        Handler(1, Scope->Frame);
    }
}

#define STRINGIFY(a) #a
#define EMIT_PRAGMA_(params) \
    _Pragma( STRINGIFY(params) )
#define EMIT_PRAGMA(type,line) \
    EMIT_PRAGMA_(REACTOS seh(type,line))

#define _SEH3$_EMIT_DEFS_AND_PRAGMA__(Line, Type)                                   \
    /* Emit assembler constants with line number to be individual */                \
    __asm__ __volatile__ goto ("\n"                                                 \
        "\t__seh2$$begin_try__" #Line "=%l0 + 1\n" /* Begin of tried code */        \
        "\t__seh2$$end_try__" #Line "=%l1 + 1\n" /* End of tried code */            \
        "\t__seh2$$filter__" #Line "=%l2\n" /* Filter function */                   \
        "\t__seh2$$begin_except__" #Line "=%l3\n" /* Called on except */            \
            : /* No output */                                                       \
            : /* No input */                                                        \
            : /* Handlers are entered with the dispatcher's registers */            \
              "memory", "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi",             \
              "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"          \
            : __seh2$$begin_try__,                                                  \
              __seh2$$end_try__,                                                    \
              __seh2$$filter__,                                                     \
              __seh2$$begin_except__);                                              \
    /* Call our home-made pragma */                                                 \
    EMIT_PRAGMA(Type,Line)

#define _SEH3$_EMIT_DEFS_AND_PRAGMA_(Line, Type) _SEH3$_EMIT_DEFS_AND_PRAGMA__(Line, Type)
#define _SEH3$_EMIT_DEFS_AND_PRAGMA(Type) _SEH3$_EMIT_DEFS_AND_PRAGMA_(__LINE__, Type)

#define _SEH2_TRY                                                                   \
{                                                                                   \
    __label__ __seh2$$filter__;                                                     \
    __label__ __seh2$$begin_except__;                                               \
    __label__ __seh2$$begin_try__;                                                  \
    __label__ __seh2$$end_try__;                                                    \
    __label__ __seh2$$setup__;                                                      \
    volatile struct __seh2_scope __seh2$$scope__                                    \
        __attribute__((cleanup(__seh2_scope_exit)));                                \
    /* Member by member: an aggregate initializer is built in a temporary and       \
       copied with a 16-byte load of two just-stored words (a failed store          \
       forward, about 12 cycles, on every system call that has a try block) */      \
    __seh2$$scope__.Handler = 0;                                                    \
    __seh2$$scope__.Frame = __builtin_frame_address(0);                             \
    __asm__ __volatile__("mov %%rsp, %0" : "=m"(__seh2$$scope__.Stack));              \
    goto __seh2$$setup__;                                                          \
    /*                                                                              \
     * We close the current SEH block for this function and install our own.        \
     * At this point GCC emitted its prologue, and if it saves more                 \
     * registers, the relevant instruction will be valid for our scope as well.     \
     * We also count the number of try blocks at assembly level                     \
     * to properly set the handler data when we're done.                            \
     */                                                                             \
__seh2$$begin_try__:                                                                \
    /* A call to a noreturn function right before returns here: keep it out */      \
    __asm__ __volatile__("nop");                                                    \
    {                                                                               \
        __label__ __seh2$$leave_scope__;                                            \
        /* Keep the handler if the block never ends, as with a noreturn call */     \
        __asm__ __volatile__ goto("" : : : : __seh2$$end_try__);

#define _SEH2_EXCEPT(...)                                                                       \
__seh2$$leave_scope__: __MINGW_ATTRIB_UNUSED;                                                   \
    }                                                                                           \
__seh2$$end_try__:(void)0;                                                                      \
    if (0)                                                                                      \
    {                                                                                           \
        __seh2$$setup__: goto __seh2$$begin_try__;                                               \
    }                                                                                           \
    /* Call our home-made pragma */                                                             \
    _SEH3$_EMIT_DEFS_AND_PRAGMA(__seh$$except);                                                 \
    if (0)                                                                                      \
    {                                                                                           \
        __label__ __seh2$$leave_scope__;                                                        \
        long __MINGW_ATTRIB_UNUSED __seh2$$exception_code__;                                    \
        /* Add our handlers to the list */                                                      \
        if (0)                                                                                  \
        {                                                                                       \
            /* Jump to the global filter. Tell it where the filter funclet lies */              \
            __label__ __seh2$$filter_funclet__;                                                 \
            __seh2$$filter__:                                                                   \
            __asm__ __volatile__ goto(                                                          \
                "\tleaq %l1(%%rip), %%r8\n"                                                     \
                "\tjmp __seh2_global_filter_func\n"                                             \
                : /* No output */                                                               \
                : "a"(__builtin_frame_address(0))                                               \
                : "%r8"                                                                         \
                : __seh2$$filter_funclet__);                                                    \
            /* Actually declare our filter funclet */                                           \
            struct _SEH$$_EXCEPTION_POINTERS* __seh2$$exception_ptr__;                                \
            __seh2$$filter_funclet__:                                                           \
            /* At this point, the compiler can't count on any register being valid */           \
            __asm__ __volatile__(""                                                             \
                : "=c"(__seh2$$exception_ptr__) /* First argument of the filter function */     \
                : /* No input */                                                                \
                : /* Everything */                                                              \
                "%rax", "%rbx","%rdx", "%rdi", "%rsi",                                          \
                "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15");                  \
            /* Save exception code */                                                           \
            __seh2$$exception_code__ = __seh2$$exception_ptr__->ExceptionRecord->ExceptionCode; \
            /* Actually evaluate our filter and return via eax */                               \
            long __seh2$$filter_funclet_ret = ((__VA_ARGS__));                                  \
            /* Go back to the global filter function with result in eax */                      \
            __asm__ __volatile__("jmp __seh2_global_filter_func_exit"                           \
                : /* No output */                                                               \
                : "a"(__seh2$$filter_funclet_ret));                                             \
        }                                                                                       \
        /* Protect us from emitting instructions to jump back to the filter function */         \
        enum                                                                                    \
        {                                                                                       \
            __seh2$$abnormal_termination__ = 0                                                  \
        };                                                                                      \
        __seh2$$begin_except__:                                                                 \
        /* A fault in a finally funclet can select an except in the parent. */                  \
        /* Restore that scope's stack instead of continuing on the funclet's stack. */          \
        __asm__ __volatile__("mov %0, %%rsp"                                                     \
            : : "m"(__seh2$$scope__.Stack) : "memory");

#define _SEH2_FINALLY                                                                       \
__seh2$$leave_scope__: __MINGW_ATTRIB_UNUSED;                                               \
    }                                                                                       \
__seh2$$end_try__:                                                                          \
__seh2$$begin_except__: __MINGW_ATTRIB_UNUSED;                                              \
    if (0)                                                                                  \
    {                                                                                       \
        __seh2$$setup__:                                                                    \
        __seh2$$scope__.Handler = (__seh2_finally_function)&&__seh2$$filter__;                \
        goto __seh2$$begin_try__;                                                           \
    }                                                                                       \
    /* Call our home-made pragma */                                                         \
    _SEH3$_EMIT_DEFS_AND_PRAGMA(__seh$$finally);                                            \
    if (1)                                                                                  \
    {                                                                                       \
        __label__ __seh2$$finally__;                                                        \
        __label__ __seh2$$begin_finally__;                                                  \
        __label__ __seh2$$leave_scope__;                                                    \
        __asm__ __volatile__ goto("" : : : : __seh2$$finally__);                            \
        int __seh2$$abnormal_termination__;                                                 \
        if (0)                                                                              \
        {                                                                                   \
            /* Jump to the global trampoline. Tell it where the unwind code really lies */  \
            __seh2$$filter__: __MINGW_ATTRIB_UNUSED;                                        \
            __seh2$$finally__: __MINGW_ATTRIB_UNUSED;                                       \
            __asm__ __volatile__ goto(                                                      \
                "\t\n"                                                                      \
                "\tleaq %l1(%%rip), %%r8\n"                                                 \
                "\tjmp __seh2_global_filter_func\n"                                         \
                : /* No output */                                                           \
                : "a"(__builtin_frame_address(0))                                           \
                : "%r8"                                                                     \
                : __seh2$$begin_finally__);                                                 \
        }                                                                                   \
                                                                                            \
        /* Zero-out rcx to indicate normal termination */                                   \
        __asm__ __volatile__("xor %%rcx, %%rcx"                                             \
            : /* No output */                                                               \
            : /* No input */                                                                \
            : /* Everything - We might come from __C_specific_handler here */               \
            "%rax", "%rbx", "%rcx", "%rdx", "%rdi", "%rsi",                                 \
            "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15");                  \
        /* Actually declare our finally funclet */                                          \
        __seh2$$begin_finally__:                                                            \
        __asm__ __volatile__(""                                                             \
            : "=c" (__seh2$$abnormal_termination__));                                       \
        __seh2$$scope__.Handler = 0;

#define _SEH2_END                                                                   \
        __seh2$$leave_scope__: __MINGW_ATTRIB_UNUSED;                               \
        if (__seh2$$abnormal_termination__)                                         \
        {                                                                           \
            __asm__("jmp __seh2_global_filter_func_exit");                          \
        }                                                                           \
    }                                                                               \
}

#define _SEH2_GetExceptionInformation() ((struct _EXCEPTION_POINTERS*)__seh2$$exception_ptr__)
#define _SEH2_GetExceptionCode() __seh2$$exception_code__
#define _SEH2_AbnormalTermination() __seh2$$abnormal_termination__
#define _SEH2_LEAVE goto __seh2$$leave_scope__
#define _SEH2_YIELD(__stmt) __stmt
#define _SEH2_VOLATILE volatile

#undef __try // undef from GCC's stl
#define __try _SEH2_TRY
#define __except _SEH2_EXCEPT
#define __finally _SEH2_FINALLY
#define __endtry _SEH2_END
#define __leave goto __seh2$$leave_scope__
#define _exception_info() ((struct _EXCEPTION_POINTERS*)__seh2$$exception_ptr__)
#define _exception_code() __seh2$$exception_code__
#define _abnormal_termination() __seh2$$abnormal_termination__
