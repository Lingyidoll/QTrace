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

/* 当前libc trace开关状态(由setBufferSize的bit3控制) */
bool is_libc_trace_enabled()
{
    return debug;
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
    if(_g_libc_trace == nullptr)
    {
        LOGE("libc trace : not init!");
        return;
    }
    size_t addr = (size_t)dlsym(handle,funcname);
    if(addr == 0)
    {
        //bionic内部实现(如__strlen_aarch64)不一定在导出表里，回退到ELF动态符号表解析
        addr = findSymbolInSo("libc.so", funcname);
        if(addr == 0 || addr == (size_t)-1)
        {
            LOGE("libc trace : %s find fail",funcname);
            return;
        }
    }
    /*
     * 先查重再分配：重复调用(例如以后在每次trace前重新同步库函数表)时
     * 不会覆盖已有的 TraceFunc，也不会泄漏一个没人引用的 new TraceFunc。
     * 同一个实现被多个名字注册时(如 strlen / __strlen_aarch64)保留第一次的名字。
     */
    auto it = _g_libc_trace->map.find(addr);
    if(it != _g_libc_trace->map.end())
    {
        LOGE("libc trace: %s:%p already installed as %s, skip",
             funcname, (void*)addr,
             it->second != nullptr && it->second->name != nullptr ? it->second->name : "?");
        return;
    }
    TraceFunc* func_trace = new TraceFunc();
    func_trace->callback = callback;
    func_trace->name = funcname;
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

/* 追加一段字节的十六进制预览，最多输出 maxBytes 个字节 */
static void appendHexBytes(const uint8_t* buf, uint64_t n, uint64_t maxBytes)
{
    uint64_t out = n < maxBytes ? n : maxBytes;
    for (uint64_t i = 0; i < out; ++i)
    {
        appendformat("%s%02x", i ? " " : "", buf[i]);
    }
    if (n > out)
    {
        appendlog(" ...");
    }
}

/*
 * 追加缓冲区预览：
 *  - 内容全是可打印字符: 输出 "字符串"；
 *  - 字符串里出现 NUL 结尾: 额外输出 [hex: xx xx]，这样 len=2 的 00 00
 *    不会只显示成 ""（看不出实际字节）；
 *  - 二进制/不可读: 输出 0x地址[hex bytes]。
 */
static void appendBufferPreview(uint64_t addr, uint64_t len, uint64_t maxLen)
{
    if (addr == 0)
    {
        appendlog("NULL");
        return;
    }
    if (len == 0)
    {
        appendlog("\"\"");
        return;
    }
    uint64_t n = len < maxLen ? len : maxLen;
    uint8_t buf[64] = {0};
    if (n > sizeof(buf))
    {
        n = sizeof(buf);
    }
    if (!safeReadMemory(addr, buf, n))
    {
        appendformat("0x%lx", addr);
        return;
    }
    bool printable = true;
    uint64_t textLen = n;
    bool terminated = false;
    for (uint64_t i = 0; i < n; ++i)
    {
        if (buf[i] == 0)
        {
            textLen = i;
            terminated = true;
            break;
        }
        if (buf[i] < 0x20 || buf[i] > 0x7e)
        {
            printable = false;
            break;
        }
    }
    if (printable)
    {
        appendlog("\"");
        appendlog_n((const char*)buf, (size_t)textLen);
        appendlog("\"");
        if (terminated)
        {
            //把字符串结尾(含 NUL)的真实字节用hex补上，空字符串也能看到 00
            appendlog(" [hex: ");
            appendHexBytes(buf, textLen + 1, 16);
            appendlog("]");
        }
    }
    else
    {
        appendformat("0x%lx[", addr);
        appendHexBytes(buf, n, 64);
        appendlog("]");
    }
}

void libc_strcmp(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
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

void libc_strncmp(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    appendlog("strncmp(");
    appendCStringArg(QBDI_GPR_GET(gprState, 0));
    appendlog(", ");
    appendCStringArg(QBDI_GPR_GET(gprState, 1));
    appendformat(", 0x%lx)", x2);
    appendlogendl();
}

void libc_strstr(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendlog("strstr(");
    appendCStringArg(QBDI_GPR_GET(gprState, 0));
    appendlog(", ");
    appendCStringArg(QBDI_GPR_GET(gprState, 1));
    appendlog(")");
    appendlogendl();
}

void libc_strcpy(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t dst = QBDI_GPR_GET(gprState, 0);
    appendformat("strcpy(dst=0x%lx, src=", dst);
    appendCStringArg(QBDI_GPR_GET(gprState, 1));
    appendlog(")");
    appendlogendl();
}

void libc_strncpy(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t dst = QBDI_GPR_GET(gprState, 0);
    uint64_t n = QBDI_GPR_GET(gprState, 2);
    appendformat("strncpy(dst=0x%lx, src=", dst);
    appendCStringArg(QBDI_GPR_GET(gprState, 1));
    appendformat(", len=0x%lx)", n);
    appendlogendl();
}

void libc_memmove(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    if(debug)
    {
        LOGE("libc memmove:%p,%p,%lx",(void*)x0,(void*)x1,x2);
    }
    appendformat("memmove(dst=0x%lx, src=", x0);
    appendBufferPreview(x1, x2, 32);
    appendformat(", len=0x%lx", x2);
    //回调在调用返回之后执行，返回值x0就是dst，此时可以读到搬运后的内容
    if ((uint64_t)g_deferred_call_retval == x0)
    {
        appendlog(", after=");
        appendBufferPreview(x0, x2, 16);
    }
    appendlog(")");
    appendlogendl();
}

void libc_memset(QBDI::VM *vm, QBDI::GPRState *gprState) {
    if (currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    appendformat("memset(addr=0x%lx, val=0x%lx, num=0x%lx)", x0, x1, x2);
    appendlogendl();
}

void libc_memcpy(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    appendformat("memcpy(dst=0x%lx, src=", x0);
    appendBufferPreview(x1, x2, 32);
    appendformat(", len=0x%lx", x2);
    //回调在调用返回之后执行，返回值x0就是dst，此时可以读到复制后的内容
    if ((uint64_t)g_deferred_call_retval == x0)
    {
        appendlog(", after=");
        appendBufferPreview(x0, x2, 16);
    }
    appendlog(")");
    appendlogendl();
}

void libc_memcmp(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("memcmp(a=0x%lx, b=0x%lx, len=0x%lx)",
                 QBDI_GPR_GET(gprState, 0),
                 QBDI_GPR_GET(gprState, 1),
                 QBDI_GPR_GET(gprState, 2));
    appendlogendl();
}

void libc_access(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendlog("access(path=");
    appendCStringArg(QBDI_GPR_GET(gprState, 0));
    appendformat(", mode=0x%lx)", QBDI_GPR_GET(gprState, 1));
    appendlogendl();
}

void libc_system_property_get(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendlog("__system_property_get(name=");
    appendCStringArg(QBDI_GPR_GET(gprState, 0));
    appendlog(")");
    appendlogendl();
}

void libc_pthread_create(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t thread = QBDI_GPR_GET(gprState, 0);
    uint64_t attr = QBDI_GPR_GET(gprState, 1);
    uint64_t routine = QBDI_GPR_GET(gprState, 2);
    uint64_t arg = QBDI_GPR_GET(gprState, 3);
    if(debug)
    {
        LOGE("libc pthread_create:%lx", routine - _g_trace_data->base);
    }
    appendformat("pthread_create(thread=0x%lx, attr=0x%lx, start_routine=", thread, attr);
    if(_g_trace_data != nullptr && routine >= _g_trace_data->base && routine < _g_trace_data->end)
    {
        appendformat("0x%lx(module+0x%lx)", routine, routine - _g_trace_data->base);
    }
    else
    {
        appendformat("0x%lx", routine);
    }
    appendformat(", arg=0x%lx)", arg);
    appendlogendl();
}

void libc_clock_gettime(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(debug)
    {
        LOGE("libc clock_gettime");
    }
    appendformat("clock_gettime(clk_id=%ld, tp=0x%lx)",
                 (long)(int32_t)(uint32_t)QBDI_GPR_GET(gprState, 0),
                 QBDI_GPR_GET(gprState, 1));
    appendlogendl();
}

void libc_exit(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(debug)
    {
        LOGE("libc exit");
    }
    appendformat("exit(status=%d)", (int)(int32_t)(uint32_t)QBDI_GPR_GET(gprState, 0));
    appendlogendl();
}

void libc_abort(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(debug)
    {
        LOGE("libc abort");
    }
    appendlog("abort()");
    appendlogendl();
}

void libc_kill(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("kill(pid=%d, sig=%d)",
                 (int)(int32_t)(uint32_t)QBDI_GPR_GET(gprState, 0),
                 (int)(int32_t)(uint32_t)QBDI_GPR_GET(gprState, 1));
    appendlogendl();
}

void libc_strlen(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    if(debug)
    {
        LOGE("libc strlen:%p",(void*)x0);
    }
    appendlog("strlen(");
    appendCStringArg(x0);
    appendlog(")");
    appendlogendl();
}

void libc_execve(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t path = QBDI_GPR_GET(gprState, 0);
    uint64_t argv = QBDI_GPR_GET(gprState, 1);
    appendlog("execve(path=");
    appendCStringArg(path);
    appendlog(", argv=[");
    //最多输出前8个参数，避免非法指针导致长时间循环
    for (int i = 0; i < 8 && argv != 0; ++i, argv += sizeof(uint64_t))
    {
        uint64_t arg = 0;
        if (!safeReadMemory(argv, (uint8_t*)&arg, sizeof(arg)) || arg == 0)
        {
            break;
        }
        if (i)
        {
            appendlog(", ");
        }
        appendCStringArg(arg);
    }
    appendlog("])");
    appendlogendl();
}

void libc_fstatat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("fstatat(dirfd=%d, path=", (int)(int32_t)(uint32_t)QBDI_GPR_GET(gprState, 0));
    appendCStringArg(QBDI_GPR_GET(gprState, 1));
    appendformat(", flags=0x%lx)", QBDI_GPR_GET(gprState, 3));
    appendlogendl();
}

void libc_stat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendlog("stat(path=");
    appendCStringArg(QBDI_GPR_GET(gprState, 0));
    appendlog(")");
    appendlogendl();
}

void libc_lstat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendlog("lstat(path=");
    appendCStringArg(QBDI_GPR_GET(gprState, 0));
    appendlog(")");
    appendlogendl();
}

void libc_fopen(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendlog("fopen(path=");
    appendCStringArg(QBDI_GPR_GET(gprState, 0));
    appendlog(", mode=");
    appendCStringArg(QBDI_GPR_GET(gprState, 1));
    appendlog(")");
    appendlogendl();
}

/* ---------------- 常用内存/文件函数 ---------------- */

void libc_malloc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("malloc(0x%lx)", QBDI_GPR_GET(gprState, 0));
    appendlogendl();
}

void libc_free(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("free(ptr=0x%lx)", QBDI_GPR_GET(gprState, 0));
    appendlogendl();
}

void libc_calloc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("calloc(nmemb=0x%lx, size=0x%lx)",
                 QBDI_GPR_GET(gprState, 0), QBDI_GPR_GET(gprState, 1));
    appendlogendl();
}

void libc_realloc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("realloc(ptr=0x%lx, size=0x%lx)",
                 QBDI_GPR_GET(gprState, 0), QBDI_GPR_GET(gprState, 1));
    appendlogendl();
}

void libc_getenv(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendlog("getenv(name=");
    appendCStringArg(QBDI_GPR_GET(gprState, 0));
    appendlog(")");
    appendlogendl();
}

void libc_open(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendlog("open(path=");
    appendCStringArg(QBDI_GPR_GET(gprState, 0));
    appendformat(", flags=0x%lx)", QBDI_GPR_GET(gprState, 1));
    appendlogendl();
}

void libc_openat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("openat(dirfd=%d, path=", (int)(int32_t)(uint32_t)QBDI_GPR_GET(gprState, 0));
    appendCStringArg(QBDI_GPR_GET(gprState, 1));
    appendformat(", flags=0x%lx)", QBDI_GPR_GET(gprState, 2));
    appendlogendl();
}

void libc_read(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("read(fd=%d, buf=0x%lx, count=0x%lx)",
                 (int)(int32_t)(uint32_t)QBDI_GPR_GET(gprState, 0),
                 QBDI_GPR_GET(gprState, 1),
                 QBDI_GPR_GET(gprState, 2));
    appendlogendl();
}

void libc_write(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("write(fd=%d, buf=", (int)(int32_t)(uint32_t)QBDI_GPR_GET(gprState, 0));
    appendBufferPreview(QBDI_GPR_GET(gprState, 1), QBDI_GPR_GET(gprState, 2), 32);
    appendformat(", count=0x%lx)", QBDI_GPR_GET(gprState, 2));
    appendlogendl();
}

void libc_close(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("close(fd=%d)", (int)(int32_t)(uint32_t)QBDI_GPR_GET(gprState, 0));
    appendlogendl();
}

/* mmap(addr, length, prot, flags, fd, offset)：返回值为映射后的地址 */
void libc_mmap(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("mmap(addr=0x%lx, length=0x%lx, prot=0x%lx, flags=0x%lx, fd=%d, offset=0x%lx)",
                 QBDI_GPR_GET(gprState, 0),
                 QBDI_GPR_GET(gprState, 1),
                 QBDI_GPR_GET(gprState, 2),
                 QBDI_GPR_GET(gprState, 3),
                 (int)(int32_t)(uint32_t)QBDI_GPR_GET(gprState, 4),
                 QBDI_GPR_GET(gprState, 5));
    appendlogendl();
}

void libc_munmap(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("munmap(addr=0x%lx, length=0x%lx)",
                 QBDI_GPR_GET(gprState, 0),
                 QBDI_GPR_GET(gprState, 1));
    appendlogendl();
}

/* dlsym(handle, symbol)：symbol是C字符串，返回解析到的函数地址 */
void libc_dlsym(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("dlsym(handle=0x%lx, symbol=", QBDI_GPR_GET(gprState, 0));
    appendCStringArg(QBDI_GPR_GET(gprState, 1));
    appendlog(")");
    appendlogendl();
}

/* strdup(s)：返回堆上新分配的字符串 */
void libc_strdup(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendlog("strdup(s=");
    appendCStringArg(QBDI_GPR_GET(gprState, 0));
    appendlog(")");
    appendlogendl();
}

/* ---------------- 线程同步函数 ---------------- */

/* pthread_mutex_lock(mutex)：x0是pthread_mutex_t*，返回0表示加锁成功 */
void libc_pthread_mutex_lock(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("pthread_mutex_lock(mutex=0x%lx)", QBDI_GPR_GET(gprState, 0));
    appendlogendl();
}

/* pthread_mutex_unlock(mutex)：x0是pthread_mutex_t*，返回0表示解锁成功 */
void libc_pthread_mutex_unlock(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("pthread_mutex_unlock(mutex=0x%lx)", QBDI_GPR_GET(gprState, 0));
    appendlogendl();
}

/* pthread_rwlock_init(rwlock, attr)：x0是pthread_rwlock_t*，attr可以为NULL */
void libc_pthread_rwlock_init(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("pthread_rwlock_init(rwlock=0x%lx, attr=0x%lx)",
                 QBDI_GPR_GET(gprState, 0),
                 QBDI_GPR_GET(gprState, 1));
    appendlogendl();
}

/* pthread_rwlock_unlock(rwlock)：x0是pthread_rwlock_t*，返回0表示解锁成功 */
void libc_pthread_rwlock_unlock(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(currentLogger() == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    appendformat("pthread_rwlock_unlock(rwlock=0x%lx)", QBDI_GPR_GET(gprState, 0));
    appendlogendl();
}
