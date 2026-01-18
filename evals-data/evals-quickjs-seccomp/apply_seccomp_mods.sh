#!/bin/bash
# Apply seccomp modifications to qjs.c and quickjs-libc.c
# This script modifies files in the current directory

set -e

if [ ! -f qjs.c ]; then
    echo "Error: qjs.c not found in current directory"
    exit 1
fi

if [ ! -f quickjs-libc.c ]; then
    echo "Error: quickjs-libc.c not found in current directory"
    exit 1
fi

# Make writable
chmod +w qjs.c

# 1. Add seccomp headers after #include <time.h>
sed -i '/#include <time.h>/a\
\
/* Seccomp headers for sandboxing */\
#ifdef __linux__\
#include <sys/prctl.h>\
#include <linux/seccomp.h>\
#include <linux/filter.h>\
#include <sys/syscall.h>\
#include <stddef.h>\
#endif' qjs.c

# 2. Remove std/os module initialization
sed -i '/js_init_module_std(ctx, "std");/d' qjs.c
sed -i '/js_init_module_os(ctx, "os");/d' qjs.c
sed -i 's|/\* system modules \*/|/* std/os modules removed for sandboxed build */|' qjs.c

# 3. Add seccomp filter function before JS_NewCustomContext
# Find the line number of JS_NewCustomContext
LINENUM=$(grep -n "^static JSContext \*JS_NewCustomContext" qjs.c | cut -d: -f1)
if [ -z "$LINENUM" ]; then
    echo "Error: Could not find JS_NewCustomContext"
    exit 1
fi

# Insert the seccomp function before JS_NewCustomContext
INSERTLINE=$((LINENUM - 1))
sed -i "${INSERTLINE}a\\
\\
/* Seccomp filter to block process execution syscalls */\\
#ifdef __linux__\\
__attribute__((used)) static int install_seccomp_filter(void)\\
{\\
    struct sock_filter filter[] = {\\
        /* Load syscall number */\\
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),\\
\\
        /* Block execve */\\
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),\\
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),\\
        /* Block execveat */\\
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),\\
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),\\
        /* Block fork */\\
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1),\\
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),\\
        /* Block vfork */\\
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 0, 1),\\
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),\\
        /* Block clone */\\
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 1),\\
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),\\
        /* Block clone3 */\\
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),\\
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),\\
\\
        /* Allow everything else */\\
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),\\
    };\\
\\
    struct sock_fprog prog = {\\
        .len = sizeof(filter) / sizeof(filter[0]),\\
        .filter = filter,\\
    };\\
\\
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)\\
        return -1;\\
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, \&prog) < 0)\\
        return -1;\\
    return 0;\\
}\\
#endif\\
" qjs.c

# 4. Add seccomp init call in main() after argument parsing
# Find the line with "if (trace_memory) {" which is right after arg parsing
TRACELINE=$(grep -n "if (trace_memory) {" qjs.c | head -1 | cut -d: -f1)
if [ -z "$TRACELINE" ]; then
    echo "Error: Could not find trace_memory check in main()"
    exit 1
fi

# Insert before trace_memory check
INSERTLINE=$((TRACELINE - 1))
sed -i "${INSERTLINE}a\\
\\
#ifdef __linux__\\
    /* Install seccomp filter before any JS execution */\\
    if (install_seccomp_filter() < 0) {\\
        fprintf(stderr, \"qjs: failed to install seccomp filter\\\\n\");\\
        exit(2);\\
    }\\
#endif\\
" qjs.c

# 5. Stub out js_init_module_std and js_init_module_os in quickjs-libc.c
# This makes all the dangerous static functions unreferenced so gc-sections removes them
chmod +w quickjs-libc.c

# Replace js_init_module_std function body with a stub that returns NULL
# Find the function and replace its body
python3 << 'PYTHON_SCRIPT'
import re

with open('quickjs-libc.c', 'r') as f:
    content = f.read()

# Stub out js_init_module_std - replace the entire function body
std_pattern = r'(JSModuleDef \*js_init_module_std\(JSContext \*ctx, const char \*module_name\))\s*\{[^}]+\}'
std_replacement = r'''\1
{
    /* Stubbed out for sandboxed build - std module disabled */
    (void)ctx;
    (void)module_name;
    return NULL;
}'''
content = re.sub(std_pattern, std_replacement, content)

# Stub out js_init_module_os - this one is more complex, need to find matching braces
# Find the start of js_init_module_os
os_start = content.find('JSModuleDef *js_init_module_os(JSContext *ctx, const char *module_name)')
if os_start != -1:
    # Find the opening brace
    brace_start = content.find('{', os_start)
    if brace_start != -1:
        # Count braces to find matching close
        depth = 1
        pos = brace_start + 1
        while depth > 0 and pos < len(content):
            if content[pos] == '{':
                depth += 1
            elif content[pos] == '}':
                depth -= 1
            pos += 1
        # Replace the function body
        func_decl = content[os_start:brace_start]
        stub_body = '''
{
    /* Stubbed out for sandboxed build - os module disabled */
    (void)ctx;
    (void)module_name;
    return NULL;
}'''
        content = content[:os_start] + func_decl + stub_body + content[pos:]

# Also remove __loadScript from js_std_add_helpers
# This line references js_loadScript which we want to remove
content = re.sub(
    r'JS_SetPropertyStr\(ctx, global_obj, "__loadScript",\s*\n\s*JS_NewCFunction\(ctx, js_loadScript, "__loadScript", 1\)\);',
    '/* __loadScript removed for sandboxed build */',
    content
)

with open('quickjs-libc.c', 'w') as f:
    f.write(content)

print("Stubbed out js_init_module_std, js_init_module_os, and removed __loadScript")
PYTHON_SCRIPT

echo "Seccomp modifications applied successfully"
