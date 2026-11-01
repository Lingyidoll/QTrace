//
// Created by zgy on 2025/11/12.
//
#include "libctrace.h"
#include "dlfcn.h"
#include "logger.h"
#include "HookUtils.h"
#include "TraceUtils.h"
LibcTraceMap* _g_libc_trace = nullptr;
static bool debug = false;

void enable_libc_trace_debug(bool enable)
{
    debug = enable;
}

void initLibcTrace()
{
    _g_libc_trace = new LibcTraceMap();
    _g_libc_trace->map.reserve(10);
}

bool hasLibctrace()
{
    if(_g_libc_trace == nullptr)
    {
        return false;
    }
    if(_g_libc_trace->map.empty())
    {
        return false;
    }
    return true;
}

void addLibctrace(void* handle,TraceCallBack callback,const char* funcname)
{
    size_t addr = (size_t)dlsym(handle,funcname);
    if(addr == 0)
    {
        LOGE("libc trace : %s find fail",funcname);
        return;
    }
    TraceFunc* func_trace = new TraceFunc();
    func_trace->callback = callback;
    if(_g_libc_trace == nullptr)
    {
        LOGE("libc trace : not init!");
        return;
    }
    auto it = _g_libc_trace->map.find(addr);
    if(it != _g_libc_trace->map.end())
    {
        LOGE("libc trace: %p has installed!",(void*)addr);
        return;
    }
    _g_libc_trace->map[addr] = func_trace;
    LOGE("libc trace: %s:%p install",funcname,(void*)addr);
}
/* 参数按C字符串输出: "xxx"，读不到时输出原始地址 */
static void appendCStringArg(uint64_t addr)
{
    if (addr == 0)
    {
        appendlog("NULL");
        return;
    }
    const size_t kMaxLen = 96;
    size_t chunkList[] = {kMaxLen + 1, 33, 17};
    for (size_t c = 0; c < sizeof(chunkList) / sizeof(chunkList[0]); ++c)
    {
        uint8_t raw[128] = {0};
        size_t len = chunkList[c];
        if (len > sizeof(raw))
        {
            len = sizeof(raw);
        }
        if (!safeReadMemory(addr, raw, len))
        {
            continue;
        }
        bool terminated = false;
        bool printable = true;
        size_t i = 0;
        for (; i < len; ++i)
        {
            if (raw[i] == 0)
            {
                terminated = true;
                break;
            }
            if (raw[i] < 0x20 || raw[i] > 0x7e)
            {
                printable = false;
                break;
            }
        }
        if (terminated && printable)
        {
            if (i > kMaxLen)
            {
                i = kMaxLen;
            }
            char buf[128] = {0};
            memcpy(buf, raw, i);
            appendformat("\"%s\"", buf);
            return;
        }
    }
    appendformat("0x%lx", addr);
}

void libc_strcmp(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    if(debug)
    {
        LOGE("libc strcmp:%p,%p",(void*)x0,(void*)x1);
    }
    appendlog("strcmp(");
    appendCStringArg(x0);
    appendlog(", ");
    appendCStringArg(x1);
    appendlog(")");
    appendlogendl();
}

void libc_memmove(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    bool bIsString = false;
    if(x2 > 1)
    {
        int len = x2 <= 10 ? x2:10;
        bIsString = isString((char*)x1,len);
        if(bIsString)
        {
            LOGE("libc memmove: %s",(char*)x1);
        }
    }
    appendlogendl();
    appendformat("[log] libc memmove: dest 0x%lx,src 0x%lx,len 0x%lx",x0,x1,x2);
    if(bIsString)
    {
        appendformat(",%s;",(char*)x1);
    }
    else{
        char* hex = bytes_to_hex_string((char*)x1,x2);
        appendformat("\n%s;",hex);
        free(hex);
    }
    appendlogendl();
}

void libc_memset(QBDI::VM *vm, QBDI::GPRState *gprState) {
    if (_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    appendlogendl();
    appendformat("libc memset:addr:%p,val:%x,num:%x",x0,x1,x2);
    appendlogendl();
}

void libc_memcpy(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    bool bIsString = false;
    if(x2 > 1)
    {
        int len = x2 <= 10 ? x2:10;
        bIsString = isString((char*)x1,len);
        if(bIsString)
        {
            LOGE("libc memcpy: %s",(char*)x1);
        }
    }
    appendlogendl();
    appendformat("[log] libc memcpy: dest 0x%lx,src 0x%lx,len 0x%lx",x0,x1,x2);
    if(bIsString)
    {
        appendformat(",%s;",(char*)x1);
    }
    else{
        char* hex = bytes_to_hex_string((char*)x1,x2);
        appendformat("\n%s;",hex);
        free(hex);
    }
    appendlogendl();
}

void libc_access(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    if(debug)
    {
        LOGE("libc access:%s",(char*)x0);
    }
    appendlogendl();
    appendlog("[log] libc access:");
    appendlog((char*)x0);
    appendlogendl();
}

void libc_system_property_get(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("qdbi hook:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    if(debug)
    {
        LOGE("libc _system_property_get:%s",(char*)x0);
    }
    appendlogendl();
    appendlog("[log] libc _system_property_get:");
    appendlog((char*)x0);
    appendlogendl();
}

void libc_pthread_create(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("qdbi hook:logger not init!");
        return;
    }
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    if(debug)
    {
        LOGE("libc pthread_create:%lx",x2 - _g_trace_data->base);
    }
    appendlogendl();
    appendformat("[log] libc pthread_create:%lx",x2 - _g_trace_data->base);
    appendlogendl();
}

void libc_clock_gettime(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(debug)
    {
        LOGE("libc clock_gettime");
    }
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    appendlogendl();
    appendformat("[log] libc clock_gettime:%p",x1);
    appendlogendl();
}

void libc_exit(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(debug)
    {
        LOGE("libc exit");
    }
    appendlogendl();
    appendformat("[log] libc exit");
    appendlogendl();
}

void libc_abort(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(debug)
    {
        LOGE("libc abort");
    }
    appendlogendl();
    appendformat("[log] libc abort");
    appendlogendl();
}

void libc_kill(QBDI::VM *vm, QBDI::GPRState *gprState)
{
}

void libc_strlen(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    if(debug)
    {
        LOGE("libc strlen:%s",(char*)x0);
    }
    appendlogendl();
    appendformat("[log] libc strlen:%s",(char*)x0);
    appendlogendl();
}

void libc_execve(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    if(debug)
    {
        LOGE("libc execv:%s",(char*)x0);
        while (true)
        {
            char* arg = *((char **)x1) ;
            if(arg == nullptr)
            {
                break;
            }
            LOGE("[log] libc execv argv:%s",arg);
            x1 += 8;
        }
    }
}

void libc_fstatat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    if(debug)
    {
        LOGE("libc fstat:%s",(char*)x1);
    }
    appendlogendl();
    appendlog("[log] libc fstat:");
    appendlog((char*)x1);
    appendlogendl();
}

void libc_stat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    if(debug)
    {
        LOGE("libc stat:%s",(char*)x0);
    }
    appendlogendl();
    appendlog("[log] libc stat:");
    appendlog((char*)x0);
    appendlogendl();
}

void libc_lstat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    if(debug)
    {
        LOGE("libc lstat:%s",(char*)x0);
    }
    appendlogendl();
    appendlog("[log] libc lstat:");
    appendlog((char*)x0);
    appendlogendl();
}

void libc_fopen(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    if(debug)
    {
        LOGE("libc fopen:%s",(char*)x0);
    }
    appendlogendl();
    appendlog("[log] libc fopen:");
    appendlog((char*)x0);
    appendlogendl();
}