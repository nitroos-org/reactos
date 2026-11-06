/*
 * PROJECT:     ReactOS SDK
 * LICENSE:     BSD Zero Clause License (https://spdx.org/licenses/0BSD)
 * PURPOSE:     Helper pragma implementation for pseh library (amd64)
 * COPYRIGHT:   Copyright 2021 Jérôme Gardou
 *              Copyright 2024 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

#include <gcc-plugin.h>
#include <plugin-version.h>
#include <function.h>
#include <rtl.h>
#include <memmodel.h>
#include <emit-rtl.h>
#include <output.h>
#include <tree-pass.h>
#include <tree.h>
#include <c-family/c-pragma.h>
#include <c-family/c-common.h>

#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <cstdio>

#if 0 // To enable tracing
#define trace(...) fprintf(stderr, __VA_ARGS__)
#else
#define trace(...)
#endif

#define is_alpha(c) (((c)>64 && (c)<91) || ((c)>96 && (c)<123))

#if defined(_WIN32) || defined(WIN32)
#define VISIBLE __declspec(dllexport)
#else
#define VISIBLE __attribute__((__visibility__("default")))
#endif

#define UNUSED __attribute__((__unused__))

int
VISIBLE
plugin_is_GPL_compatible = 1;

constexpr size_t k_header_statement_max_size = 20000;

struct seh_handler
{
    bool is_except;
    unsigned int line;
};

struct seh_function
{
    bool unwind;
    bool except;
    tree asm_header_text;
    tree asm_header;
    size_t count;
    std::vector<seh_handler> handlers;

    seh_function(struct function* fun)
        : unwind(false)
        , except(false)
        , count(0)
    {
        /* Reserve space for our header statement */
#if 0 // FIXME: crashes on older GCC
        asm_header_text = build_string(k_header_statement_max_size, "");
#else
        char buf[k_header_statement_max_size];
        memset(buf, 0, sizeof(buf));
        asm_header_text = build_string(sizeof(buf), buf);
#endif
        asm_header = build_stmt(fun->function_start_locus, ASM_EXPR, asm_header_text, NULL_TREE, NULL_TREE, NULL_TREE, NULL_TREE);
        ASM_VOLATILE_P(asm_header) = 1;
        add_stmt(asm_header);
    }
};

static std::unordered_map<struct function*, struct seh_function*> func_seh_map = {};
static bool have_seh_functions = false;

static
struct seh_function*
get_seh_function()
{
    auto search = func_seh_map.find(cfun);
    if (search != func_seh_map.end())
        return search->second;

    auto seh_fun = new seh_function(cfun);
    func_seh_map.insert({cfun, seh_fun});

    return seh_fun;
}

/*
 * SEH handlerdata is emitted per source function by this plugin.
 * If such a function gets inlined, GCC concatenates multiple handlerdata
 * blocks in the caller's xdata. __C_specific_handler expects one block.
 * Prevent inlining/cloning at the producer side to keep one canonical block.
 */
static
void
mark_seh_function_noinline(void)
{
    tree fndecl = current_function_decl;

    if (fndecl == NULL_TREE)
        return;

    DECL_UNINLINABLE(fndecl) = 1;
    DECL_DECLARED_INLINE_P(fndecl) = 0;
}

/*
 * The scope table describes a try block as one address range, from its
 * begin label to its end label. Block reordering, jump threading and tail
 * merging can move code of the block past these labels (VRP threads jumps
 * too, and puts the copied blocks behind the end of the function), and a tail call
 * leaves the frame: exceptions raised there bypass the handler. Handlers can
 * also run in the middle of the block, where GCC believes a variable that a
 * handler reads is dead and lets another one share its stack slot. Turn all
 * of these off for functions using SEH.
 */
static
void
keep_seh_blocks_contiguous(void)
{
    tree fndecl = current_function_decl;

    if (fndecl == NULL_TREE)
        return;

    /* Done already, or the function has its own optimization options */
    if (DECL_FUNCTION_SPECIFIC_OPTIMIZATION(fndecl) != NULL_TREE)
        return;

    struct gcc_options opts = global_options;
    opts.x_flag_reorder_blocks = 0;
    opts.x_flag_reorder_blocks_and_partition = 0;
    opts.x_flag_thread_jumps = 0;
    opts.x_flag_tree_dom = 0;
    opts.x_flag_tree_vrp = 0;
    opts.x_flag_crossjumping = 0;
    opts.x_flag_tree_tail_merge = 0;
    opts.x_flag_optimize_sibling_calls = 0;
    opts.x_flag_ira_share_spill_slots = 0;
    opts.x_flag_ira_share_save_slots = 0;
    opts.x_flag_stack_reuse = SR_NONE;
#if GCCPLUGIN_VERSION_MAJOR >= 11
    DECL_FUNCTION_SPECIFIC_OPTIMIZATION(fndecl) = build_optimization_node(&opts, &global_options_set);
#else
    DECL_FUNCTION_SPECIFIC_OPTIMIZATION(fndecl) = build_optimization_node(&opts);
#endif
}

static
void
handle_seh_pragma(cpp_reader* UNUSED parser)
{
    tree x, arg, line;
    std::stringstream label_decl;
    bool is_except;

    if (!cfun)
    {
        error("%<#pragma REACTOS seh%> is not allowed outside functions");
        return;
    }

    if ((pragma_lex(&x) != CPP_OPEN_PAREN) ||
        (pragma_lex(&arg) != CPP_NAME) || // except or finally
        (pragma_lex(&x) != CPP_COMMA) ||
        (pragma_lex(&line) != CPP_NUMBER) || // Line number
        (pragma_lex(&x) != CPP_CLOSE_PAREN) ||
        (pragma_lex(&x) != CPP_EOF)
        )
    {
        error("%<#pragma REACTOS seh%> needs two parameters%>");
        return;
    }

    trace(stderr, "Pragma: %s, %u\n", IDENTIFIER_POINTER(arg), TREE_INT_CST_LOW(line));

    const char* op = IDENTIFIER_POINTER(arg);

    seh_function* seh_fun = get_seh_function();
    if (strcmp(op, "__seh$$except") == 0)
    {
        is_except = true;
        seh_fun->except = true;
    }
    else if (strcmp(op, "__seh$$finally") == 0)
    {
        is_except = false;
        seh_fun->unwind = true;
    }
    else
    {
        error("Wrong argument for %<#pragma REACTOS seh%>. Expected \"except\" or \"finally\"");
        return;
    }
    seh_fun->count++;

    seh_fun->handlers.push_back({is_except, (unsigned int)TREE_INT_CST_LOW(line)});

    /* Make sure we use a frame pointer. REACTOS' PSEH depends on this */
    cfun->machine->accesses_prev_frame = 1;

    /* Keep handlerdata generation canonical: one SEH block per function. */
    mark_seh_function_noinline();

    keep_seh_blocks_contiguous();
}


static
tree
make_local_volatile(tree* tp, int* walk_subtrees, void* data)
{
    tree t = *tp;

    if ((TREE_CODE(t) == VAR_DECL || TREE_CODE(t) == PARM_DECL) &&
        DECL_CONTEXT(t) == (tree)data &&
        !TREE_STATIC(t) &&
        !DECL_EXTERNAL(t) &&
        !(TREE_CODE(t) == VAR_DECL && DECL_HARD_REGISTER(t)))
    {
        TREE_THIS_VOLATILE(t) = 1;
        TREE_SIDE_EFFECTS(t) = 1;
    }
    if (walk_subtrees != NULL && TYPE_P(t))
        *walk_subtrees = 0;
    return NULL_TREE;
}

/*
 * A handler runs while its try block is in progress, but GCC assumes it runs
 * after the block: a variable may still sit in a register, its store may be
 * moved past the call that raised, or a value set before the block may only
 * be stored at its end. The handler, and the code after an except block,
 * then read stale values. Make the local variables and parameters of a
 * function that uses SEH volatile, so that their values in memory are
 * always current.
 */
static
void
make_seh_function_locals_volatile(tree fndecl)
{
    for (tree parm = DECL_ARGUMENTS(fndecl); parm != NULL_TREE; parm = DECL_CHAIN(parm))
        make_local_volatile(&parm, NULL, fndecl);
    walk_tree(&DECL_SAVED_TREE(fndecl), make_local_volatile, fndecl, NULL);
}

static
void
finish_seh_function(void* event_data, void* UNUSED user_data)
{
    tree fndef = (tree)event_data;
    struct function* fun = DECL_STRUCT_FUNCTION(fndef);

    auto search = func_seh_map.find(fun);
    if (search == func_seh_map.end())
        return;

    /* Template instantiations inherit the completed assembler statement. */
    seh_function* seh_fun = search->second;
    func_seh_map.erase(search);
    have_seh_functions = true;

    make_seh_function_locals_volatile(fndef);

    if (DECL_FUNCTION_PERSONALITY(fndef) != nullptr)
    {
        error("Function %s has a personality. Are you mixing SEH with C++ exceptions ?",
              IDENTIFIER_POINTER(fndef));
        return;
    }

    /* Update asm statement */
    std::stringstream asm_str;
    asm_str << ".seh_handler __C_specific_handler";
    if (seh_fun->unwind)
        asm_str << ", @unwind";
    if (seh_fun->except)
        asm_str << ", @except";
    asm_str << "\n";
    asm_str << "\t.seh_handlerdata\n";
    asm_str << "\t.long " << seh_fun->count << "\n";

    for (auto& handler : seh_fun->handlers)
    {
        asm_str << "\n\t.rva " << "__seh2$$begin_try__" << handler.line; /* Begin of tried code */
        asm_str << "\n\t.rva " << "__seh2$$end_try__" << handler.line; /* End of tried code */
        asm_str << "\n\t.rva " << "__seh2$$filter__" << handler.line; /* Filter function */
        if (handler.is_except)
            asm_str << "\n\t.rva " << "__seh2$$begin_except__" << handler.line; /* Called on except */
        else
            asm_str << "\n\t.long 0"; /* No unwind handler */
    }
    asm_str << "\n\t.seh_code\n";

    strncpy(const_cast<char*>(TREE_STRING_POINTER(seh_fun->asm_header_text)),
            asm_str.str().c_str(),
            TREE_STRING_LENGTH(seh_fun->asm_header_text));

    trace(stderr, "ASM: %s\n", asm_str.str().c_str());
    delete seh_fun;
}

/* A funclet uses its parent's RBP for locals but the trampoline's RSP for
 * calls. Reserve the largest outgoing argument area in this translation unit.
 * Measuring every emitted function also covers template instantiations and
 * compiler clones, which have different function objects from the parser. */
static HOST_WIDE_INT seh_outgoing_size = 32;

static
void
record_outgoing_arguments(void* event_data, void* UNUSED user_data)
{
    /* final releases the RTL state; read it while constructing the prologue. */
    opt_pass* pass = (opt_pass*)event_data;
    if (!pass->name || strcmp(pass->name, "pro_and_epilogue") != 0)
        return;

#if GCCPLUGIN_VERSION_MAJOR >= 8
    HOST_WIDE_INT size = crtl->outgoing_args_size.to_constant();
#else
    HOST_WIDE_INT size = crtl->outgoing_args_size;
#endif
    if (size > seh_outgoing_size)
        seh_outgoing_size = size;
}

static
void
emit_seh_trampoline(void* UNUSED event_data, void* UNUSED user_data)
{
    if (!have_seh_functions)
        return;

    /* Eight pushes preserve alignment; include the return address when
     * aligning the outgoing area to the Windows x64 calling convention. */
    HOST_WIDE_INT xmm_offset = (seh_outgoing_size + 15) & ~15;
    HOST_WIDE_INT allocation = xmm_offset + 10 * 16 + 8;
    fprintf(asm_out_file,
        "\n\t.text\n\t.p2align 4, 0x90\n"
        "\t.seh_proc __seh2_global_filter_func\n"
        "__seh2_global_filter_func:\n"
        /* RAX is the builtin frame address; recover its offset from RBP. */
        "\tsub %%rbp, %%rax\n");
    const char* saved[] = {"rbp", "rbx", "rdi", "rsi", "r12", "r13", "r14", "r15"};
    for (const char* reg : saved)
        fprintf(asm_out_file, "\tpush %%%s\n\t.seh_pushreg %%%s\n", reg, reg);
    if (allocation >= 4096)
    {
        /* Touch each page before moving RSP, so a large outgoing area cannot
         * jump over the stack guard. R10 and R11 are volatile scratch registers. */
        fprintf(asm_out_file,
            "\tlea -" HOST_WIDE_INT_PRINT_DEC "(%%rsp), %%r11\n"
            "\tmov %%rsp, %%r10\n"
            "1:\n\tsub $4096, %%r10\n"
            "\tcmp %%r11, %%r10\n\tjb 2f\n"
            "\ttestb $0, (%%r10)\n\tjmp 1b\n"
            "2:\n\ttestb $0, (%%r11)\n",
            allocation);
    }
    fprintf(asm_out_file,
        "\tsub $" HOST_WIDE_INT_PRINT_DEC ", %%rsp\n"
        "\t.seh_stackalloc " HOST_WIDE_INT_PRINT_DEC "\n",
        allocation, allocation);
    /* Cleanup calls have the same nonvolatile-register contract as any C call. */
    for (unsigned int reg = 6; reg <= 15; ++reg)
    {
        HOST_WIDE_INT offset = xmm_offset + (reg - 6) * 16;
        fprintf(asm_out_file,
            "\tmovaps %%xmm%u, " HOST_WIDE_INT_PRINT_DEC "(%%rsp)\n"
            "\t.seh_savexmm %%xmm%u, " HOST_WIDE_INT_PRINT_DEC "\n",
            reg, offset, reg, offset);
    }
    fprintf(asm_out_file,
        "\t.seh_endprologue\n"
        "\tsub %%rax, %%rdx\n"
        "\tmov %%rdx, %%rbp\n"
        "\tjmp *%%r8\n"
        "__seh2_global_filter_func_exit:\n");
    for (unsigned int reg = 6; reg <= 15; ++reg)
        fprintf(asm_out_file, "\tmovaps " HOST_WIDE_INT_PRINT_DEC "(%%rsp), %%xmm%u\n",
                xmm_offset + (reg - 6) * 16, reg);
    fprintf(asm_out_file, "\tadd $" HOST_WIDE_INT_PRINT_DEC ", %%rsp\n", allocation);
    for (int i = 7; i >= 0; --i)
        fprintf(asm_out_file, "\tpop %%%s\n", saved[i]);
    fprintf(asm_out_file, "\tret\n\t.seh_endproc\n");
}

static
void
register_seh_pragmas(void* UNUSED event_data, void* UNUSED user_data)
{
    c_register_pragma("REACTOS", "seh", handle_seh_pragma);
}

/* Return 0 on success or error code on failure */
extern "C"
VISIBLE
int plugin_init(struct plugin_name_args   *info,  /* Argument infor */
                struct plugin_gcc_version *version)   /* Version of GCC */
{
    if (!plugin_default_version_check (version, &gcc_version))
    {
        std::cerr << "This GCC plugin is for version " << GCCPLUGIN_VERSION_MAJOR << "." << GCCPLUGIN_VERSION_MINOR << "\n";
        return 1;
    }

    register_callback(info->base_name, PLUGIN_PRAGMAS, register_seh_pragmas, NULL);
    register_callback(info->base_name, PLUGIN_FINISH_PARSE_FUNCTION, finish_seh_function, NULL);

    register_callback(info->base_name, PLUGIN_PASS_EXECUTION, record_outgoing_arguments, NULL);
    register_callback(info->base_name, PLUGIN_FINISH_UNIT, emit_seh_trampoline, NULL);

    return 0;
}
