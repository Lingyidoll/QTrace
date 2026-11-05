//
// Created by zgy on 2025/11/12.
//

#ifndef QBDI_LIBCTRACE_H
#define QBDI_LIBCTRACE_H
#include "vm.h"
#include <unordered_map>

struct LibcTraceMap {
    std::unordered_map<size_t, TraceFunc*> map;
};

extern LibcTraceMap* _g_libc_trace;

bool hasLibctrace();
void initLibcTrace();
void addLibctrace(void* handle,TraceCallBack callback,const char* funcname);
/* 当前libc trace开关状态(由setBufferSize的bit3控制) */
bool is_libc_trace_enabled();

void libc_access(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_system_property_get(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_memcpy(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_memmove(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_memcmp(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_pthread_create(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_fopen(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_lstat(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_execve(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_clock_gettime(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_stat(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_fstatat(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_kill(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_abort(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_exit(QBDI::VM *vm, QBDI::GPRState *gprState);
void enable_libc_trace_debug(bool enable);
void libc_strlen(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_memset(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_strcmp(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_strncmp(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_strstr(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_strcpy(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_strncpy(QBDI::VM *vm, QBDI::GPRState *gprState);
/* 常用内存/文件函数 */
void libc_malloc(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_free(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_calloc(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_realloc(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_getenv(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_open(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_openat(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_read(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_write(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_close(QBDI::VM *vm, QBDI::GPRState *gprState);

#endif //QBDI_LIBCTRACE_H
