//
// Created by fang on 23-12-19.
//
#include "fstream"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <sstream>
#include <unordered_map>
#include <sys/uio.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <string>
#include <dlfcn.h>
#include <mutex>
#include <cstdarg>
#include <QBDI/Callback.h>
#include "QBDI/Memory.h"
#include "vm.h"
#include "logger.h"
#include "qbdihook.h"
#include "jnitrace.h"
#include "libctrace.h"
#include "TraceLogger.h"
#include "TraceUtils.h"
#include "HookUtils.h"
using namespace std;
using namespace QBDI;

/* trace过程中使用的模块信息，jni/libc trace回调通过它计算模块内偏移 */
static g_trace_data g_trace_data_storage{};
/* thread_local：让不同线程/嵌套trace各看各的模块信息（trace_call 里保存/恢复） */
thread_local g_trace_data* _g_trace_data = &g_trace_data_storage;
/* thread_local：多线程/嵌套trace时每个线程各存一份，避免返回值/回调名串台 */
thread_local size_t g_deferred_call_retval = 0;
thread_local const char* g_deferred_call_name = nullptr;
thread_local void* g_deferred_call_env = nullptr;
int bufsize = 0x1000000;
int bufstate = 0;
bool debugInsn = false;

/* bit4(TRACE_CFG_STOP_BEFORE_ART) 命中时为true：本次trace没有跑完，是主动停的 */
static thread_local bool g_stopped_at_cross = false;

bool trace_stopped_at_cross()
{
    return g_stopped_at_cross;
}

/* 上一条已执行指令的地址。thread_local + trace_call 里保存/恢复，支持嵌套trace。
 * 注意：必须声明在 trace_call 之前（showPreInstruction 里也在用）。 */
static thread_local size_t lastAddr = 0;

void setBufferSize(int size)
{
    /*
     * 32位打包值:
     *   bit7 .. bit0   : 配置状态，按 initTraceEnv 里 enable_* 的调用顺序从bit0开始:
     *                    bit0 enableDebugInsn        (逐指令日志)
     *                    bit1 enable_jni_trace_debug (jni trace)
     *                    bit2 enable_jni_resolve     (obj类名解析，method/field名始终由hook记录)
     *                    bit3 enable_libc_trace_debug(libc trace)
     *                    bit4 TRACE_CFG_STOP_BEFORE_ART(安全模式：进ART/未知模块前停止trace)
     *   bit31.. bit8   : 累计写盘阈值，等价字节数 = 值 & 0xFFFFFF00
     * 例如:
     *   0x10000000 = 256MB, state=0x00
     *   0x1000001A = 256MB, state=0x1A (jni trace + libc trace + 跨模块调用前停止)
     *   0x1000001E = 256MB, state=0x1E (额外打开obj类名解析)
     * 阈值部分为0时表示每 trace 一条指令就写入本地。
     */
    uint32_t value = (uint32_t)size;
    bufstate = (int)(value & 0xFFu);
    uint32_t bytes = value & 0xFFFFFF00u;
    //bufsize是int，超过int上限时截断，避免变成负数导致永远不写盘
    if (bytes > 0x7FFFFF00u)
    {
        bytes = 0x7FFFFF00u;
    }
    bufsize = (int)bytes;

    //低8位配置状态直接应用到对应开关
    // 逐条打印
    enableDebugInsn((bufstate & (1 << 0)) != 0);
    enable_jni_trace_debug((bufstate & (1 << 1)) != 0);
    // 解析类名和methodId
    enable_jni_resolve((bufstate & (1 << 2)) != 0);
    enable_libc_trace_debug((bufstate & (1 << 3)) != 0);

    LOGE("setBufferSize: raw=0x%x, state=0x%x, flushThreshold=%u bytes(%u MB)",
         value, (unsigned)bufstate, bytes, bytes >> 20);
    LOGE("trace config: debugInsn=%d, jniTrace=%d, jniResolve=%d, libcTrace=%d, stopAtCrossModule=%d",
         (bufstate & (1 << 0)) ? 1 : 0, (bufstate & (1 << 1)) ? 1 : 0,
         (bufstate & (1 << 2)) ? 1 : 0, (bufstate & (1 << 3)) ? 1 : 0,
         (bufstate & TRACE_CFG_STOP_BEFORE_ART) ? 1 : 0);
}

void enableDebugInsn(bool enable)
{
    debugInsn = enable;
}

static inline uintptr_t get_current_sp() {
    uintptr_t sp;
    __asm__ __volatile__("mov %0, sp" : "=r"(sp)); // 读取SP寄存器到sp变量
    return sp;
}

// 一条指令涉及的寄存器：写寄存器输出 before -> after，读寄存器输出当前值
struct RegRec {
    int      idx;
    bool     write;
    uint64_t before;
    uint64_t forceAfter;   // 非0时直接作为after（如bl/blr里的LR=返回地址）
    char     name[8];
};

// pending:暂存上一条指令待补全的信息
struct PendingInst {
    bool valid = false;
    char line[512];          // "0x地址\t0x偏移\t\t助记符\t操作数\t"
    int  lineLen = 0;
    RegRec regs[16];
    int  numRegs = 0;
    char memInfo[1024];      // 内存访问行(可能多条)
    int  memLen = 0;
    char syscallInfo[256];   // syscall行(svc: 系统调用号+参数)，紧跟指令行输出
    int  syscallLen = 0;
    char callHead[512];      // Call addr（已hook函数只输出 "Call addr: "，参数行由回调补全）
    int  callHeadLen = 0;
    TraceCallBack deferredCb = nullptr;  // jni/libc trace回调，延迟到调用行之后执行
    const char* deferredCbName = nullptr; // 对应函数名
    bool libcHooked = false;             // 已注册的是libc函数，需要额外输出返回值
    QBDI::GPRState snapshot{};           // 调用前的寄存器快照
    bool hasSnapshot = false;
};

/* thread_local：每次trace(含嵌套)各自一份，避免两条日志的 pending 互相覆盖 */
static thread_local PendingInst pending;

// 记录一个寄存器，同一个寄存器只保留一条（读+写合并为写）
static void appendRegRec(const char *name, int idx, uint64_t value, bool write, uint64_t forceAfter)
{
    if (name == nullptr)
    {
        return;
    }
    for (int i = 0; i < pending.numRegs; ++i)
    {
        if (pending.regs[i].idx == idx)
        {
            if (write)
            {
                pending.regs[i].write = true;
                pending.regs[i].forceAfter = forceAfter;
            }
            return;
        }
    }
    if (pending.numRegs >= (int)(sizeof(pending.regs) / sizeof(pending.regs[0])))
    {
        return;
    }
    RegRec &r = pending.regs[pending.numRegs++];
    r.idx = idx;
    r.write = write;
    r.before = value;
    r.forceAfter = forceAfter;
    snprintf(r.name, sizeof(r.name), "%s", name);
}

// 把 pending(上一条指令)用当前寄存器状态补全并输出
static void flushPending(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if (!pending.valid) return;

    // 指令行: "0x地址\t0x偏移\t\t助记符\t操作数\t"
    appendlog_n(pending.line, pending.lineLen);

    // 寄存器: X1=0xold -> 0xnew, SP=0x...
    if (pending.numRegs > 0) {
        char wbuf[512];
        int woff = 0;
        for (int i = 0; i < pending.numRegs; ++i) {
            RegRec &r = pending.regs[i];
            uint64_t after = r.forceAfter != 0 ? r.forceAfter : QBDI_GPR_GET(gprState, r.idx);
            int n;
            if (r.write && r.before != after) {
                n = snprintf(wbuf + woff, sizeof(wbuf) - woff, "%s%s=0x%" PRIx64 " -> 0x%" PRIx64,
                             i ? ", " : "", r.name, r.before, after);
            } else {
                n = snprintf(wbuf + woff, sizeof(wbuf) - woff, "%s%s=0x%" PRIx64,
                             i ? ", " : "", r.name, r.write ? after : r.before);
            }
            if (n < 0) { woff = 0; break; }
            woff += n;
            if (woff >= (int)sizeof(wbuf)) { woff = sizeof(wbuf) - 1; break; }
        }
        appendlog(";");
        appendlog_n(wbuf, woff);
    }
    appendlogendl();
    if (pending.syscallLen > 0) {
        appendlog_n(pending.syscallInfo, pending.syscallLen);
    }
    if (pending.memLen > 0) {
        appendlog_n(pending.memInfo, pending.memLen);
    }
    if (pending.callHeadLen > 0) {
        appendlog_n(pending.callHead, pending.callHeadLen);
    }
    // jni/libc trace回调放在调用行之后执行，保证 "指令行 / Call addr / 参数 / 返回值" 的顺序
    if (pending.deferredCb != nullptr) {
        // 回调在调用返回之后执行，x0此时是调用返回值
        g_deferred_call_retval = (size_t)QBDI_GPR_GET(gprState, QBDI::REG_RETURN);
        // JNI函数x0是JNIEnv，必须用被trace代码自己的env解析jobject/jmethodID
        g_deferred_call_env = pending.hasSnapshot
                                  ? (void *)QBDI_GPR_GET(&pending.snapshot, 0)
                                  : (void *)QBDI_GPR_GET(gprState, 0);
        g_deferred_call_name = pending.deferredCbName;
        pending.deferredCb(vm, pending.hasSnapshot ? &pending.snapshot : gprState);
        g_deferred_call_name = nullptr;
        g_deferred_call_env = nullptr;
        //libc函数统一在参数行之后输出返回值，jni回调自己输出带类型的返回值
        //free/abort/exit 无返回值(或不会返回)，不输出 return 行
        if (pending.libcHooked && pending.deferredCbName != nullptr &&
            strcmp(pending.deferredCbName, "free") != 0 &&
            strcmp(pending.deferredCbName, "abort") != 0 &&
            strcmp(pending.deferredCbName, "exit") != 0) {
            appendformat("       return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
        }
    }
    pending.valid = false;
}

/*
 * 定位地址所属的ELF模块。
 * 优先使用dladdr：部分加固so会被重命名，或者内嵌在apk中被直接mmap，
 * 此时/proc/self/maps里的路径不可靠，dladdr可以拿到正确的模块基址；
 * maps解析只用来补全模块结束地址。
 */
static MapItemInfo resolveModuleInfo(void *address)
{
    MapItemInfo info{0, 0};
    Dl_info dl_info{};
    if (dladdr(address, &dl_info) != 0 && dl_info.dli_fbase != nullptr)
    {
        info.start = reinterpret_cast<size_t>(dl_info.dli_fbase);
    }
    MapItemInfo maps_info = getSoBaseAddressFromAddress(address);
    if (info.start == 0)
    {
        info.start = maps_info.start;
    }
    info.end = maps_info.end > info.start ? maps_info.end : 0;
    info.size = info.end > info.start ? info.end - info.start : 0;
    return info;
}

/* 获取地址所在的可执行映射段，作为模块解析失败时的兜底instrument范围 */
static bool getExecRangeOfAddr(size_t addr, size_t &start, size_t &end)
{
    size_t count = 0;
    qbdi_MemoryMap *maps = qbdi_getCurrentProcessMaps(false, &count);
    if (maps == nullptr)
    {
        return false;
    }
    bool found = false;
    for (size_t i = 0; i < count; i++)
    {
        if ((maps[i].permission & QBDI_PF_EXEC) != 0 &&
            addr >= (size_t)maps[i].start && addr < (size_t)maps[i].end)
        {
            start = (size_t)maps[i].start;
            end = (size_t)maps[i].end;
            found = true;
            break;
        }
    }
    qbdi_freeMemoryMapArray(maps, count);
    return found;
}

/*
 * 支持"同时 trace 多个函数"：
 *   - 去掉了原来的全局互斥锁和"同线程禁止重入"的限制（由调用方自己保证时序/地址）；
 *   - 每个trace的 logger / pending / lastAddr / 模块信息 / 反汇编缓存都按线程隔离，
 *     嵌套trace在 trace_call 进出时保存/恢复，所以两份日志不会互相写乱。
 */
static thread_local int g_trace_depth = 0;

bool is_trace_running()
{
    return g_trace_depth > 0;
}

size_t trace_call(void *func_addr, const size_t *args, size_t arg_num, const char *log_path)
{
    LOGE("trace_call enter:%p,arg_num:%zu,log:%s", func_addr, arg_num,
         log_path != nullptr ? log_path : "default");
    if (func_addr == nullptr)
    {
        LOGE("trace_call: target function is null");
        return 0;
    }
    if (args == nullptr && arg_num != 0)
    {
        LOGE("trace_call: args is null but arg_num is %zu", arg_num);
        return 0;
    }
    if (arg_num > 8)
    {
        LOGE("trace_call: too many args(%zu), only 8 register args are supported", arg_num);
        return 0;
    }
    size_t function_address = reinterpret_cast<size_t>(func_addr);
    MapItemInfo soinfo = resolveModuleInfo(func_addr);
    if (soinfo.start == 0)
    {
        LOGE("trace_call: fail to find the module of %p", func_addr);
        return 0;
    }
    //部分加固so的代码段是匿名映射(或路径带空格)，maps里按路径找不到结束地址，
    //此时退化为用所在可执行段结束地址，避免end为0影响后续范围判断
    if (soinfo.end <= soinfo.start)
    {
        size_t exec_start = 0;
        size_t exec_end = 0;
        if (getExecRangeOfAddr(function_address, exec_start, exec_end))
        {
            soinfo.end = exec_end;
            LOGE("trace_call: module end fallback to exec range:[%p-%p]",
                 (void *)exec_start, (void *)exec_end);
        }
    }

    /*
     * 允许同时/嵌套 trace 多个函数：不再加锁、不再拒绝重入。
     * 每次 trace 用自己的一份状态（logger / 模块信息 / pending / lastAddr），
     * 用一个 RAII guard 在进出时保存与恢复，保证嵌套时外层日志不被写乱。
     */
    struct StateGuard
    {
        logger*           prev_logger;
        g_trace_data*     prev_data;
        g_trace_data      my_data;
        PendingInst       prev_pending;
        size_t            prev_lastaddr;
        bool              prev_stopped;
        int               prev_depth;
        ~StateGuard()
        {
            _g_trace_data      = prev_data;
            pending            = prev_pending;
            lastAddr           = prev_lastaddr;
            g_stopped_at_cross = prev_stopped;
            g_trace_depth      = prev_depth;
            swapLogger(prev_logger);
        }
    } guard{currentLogger(), _g_trace_data, {}, pending, lastAddr, g_stopped_at_cross, g_trace_depth};

    g_trace_depth = guard.prev_depth + 1;
    _g_trace_data = &guard.my_data;
    _g_trace_data->base = soinfo.start;
    _g_trace_data->start = soinfo.start;
    _g_trace_data->end = soinfo.end;
    pending.valid = false;
    lastAddr = 0;
    g_stopped_at_cross = false;

    //先创建日志文件：这样即使后面QBDI初始化/执行时崩溃，也能通过日志文件是否存在判断执行到了哪一步
    initLoggerWithPath(log_path,function_address);
    logger* lg = currentLogger();
    LOGE("start trace:%p,module:[%p-%p],depth=%d,log:%s", func_addr,
         (void *)_g_trace_data->start, (void *)_g_trace_data->end, g_trace_depth,
         lg != nullptr ? lg->logfile.c_str() : "?");
    struct timeval start, end;
    gettimeofday(&start, nullptr);

    vm* vm_ = new vm();
    auto qvm = vm_->init(_g_trace_data->base,function_address);
    LOGE("vm init done");
    auto qbdi_state = qvm.getGPRState();
    if (qbdi_state == nullptr)
    {
        LOGE("trace_call: get gpr state fail");
        writelog();
        deleteLogger();
        delete vm_;
        /* depth/logger/pending 由 StateGuard 析构恢复 */
        return 0;
    }
    vm_->base = _g_trace_data->base;
    //在当前栈上开辟栈，不使用allocateVirtualStack，防止libart中Thread crash
    size_t sp = get_current_sp();
    size_t stack_size = 0x4000;
    QBDI_GPR_SET(qbdi_state, QBDI::REG_SP, sp - stack_size);
    QBDI_GPR_SET(qbdi_state, QBDI::REG_BP, QBDI_GPR_GET(qbdi_state, QBDI::REG_SP));
    QBDI::rword qbdi_retval = 0;
    g_stopped_at_cross = false;
    LOGE("trace begin");
    //参数按AAPCS64约定通过x0~x7传入
    bool qbdi_success = qvm.callA(&qbdi_retval, (QBDI::rword)function_address,
                                  (uint32_t)arg_num,
                                  reinterpret_cast<const QBDI::rword *>(args));
    LOGE("trace end");
    /*
     * 诊断日志：目标函数的返回值/调用是否成功/SP是否被完好恢复。
     * 典型场景：加固so的 JNI_OnLoad 在QBDI下可能返回非法版本号(0)，ART会判定loadLibrary失败，
     * 接着在构造 UnsatisfiedLinkError 时走 StackVisitor 遍历被QBDI改写过的栈而崩溃。
     */
    LOGE("trace result: success=%d, retval=0x%lx, sp=0x%lx(expected 0x%lx)",
         qbdi_success ? 1 : 0, (uint64_t)qbdi_retval,
         (uint64_t)QBDI_GPR_GET(qbdi_state, QBDI::REG_SP), (uint64_t)(sp - stack_size));
    flushPending(nullptr, qbdi_state);
    writelog();
    const char* logfile = lg != nullptr ? lg->logfile.c_str() : "?";
    if (g_stopped_at_cross) {
        LOGE("trace stopped by TRACE_CFG_STOP_BEFORE_ART(bit4): target code was about to enter ART,"
             " caller must run the real function natively, log:%s", logfile);
    } else if (qbdi_success) {
        LOGE("trace completed successfully %s", logfile);
    } else {
        LOGE("trace failed");
    }
    gettimeofday(&end, nullptr);
    long elapsed_sec;
    elapsed_sec = (end.tv_sec - start.tv_sec) +
                  (end.tv_usec - start.tv_usec) / 1000000;
    LOGI("trace time cost:%lds",elapsed_sec);
    deleteLogger();
    delete vm_;
    /* g_tracing/depth/logger/pending 等由 StateGuard 析构时恢复（支持嵌套trace） */
    if (g_stopped_at_cross) {
        //目标函数没跑完，返回值没有意义：返回0，由调用方用原生执行的结果
        return 0;
    }
    return qbdi_success ? (size_t)qbdi_retval : 0;
}

bool checkAndCallHook(QBDI::VM *vm, QBDI::GPRState *gprState,size_t addr,size_t lastaddr)
{
    if(_g_hook_data == nullptr)
    {
        return false;
    }
    auto it = _g_hook_data->hookMap.find(addr);
    if(it != _g_hook_data->hookMap.end())
    {
        if(it->second->ignore != nullptr && it->second->ignorenum != 0)
        {
            for(int i=0;i<it->second->ignorenum;i++)
            {
                if(it->second->ignore[i] == lastaddr)
                {
                    return false;
                }
            }
        }
        it->second->callback(vm,gprState);
        return true;
    }
    return false;
}

/* 查找目标地址对应的jni trace回调（加锁查表，支持多线程同时trace） */
static TraceFunc* findJniTraceFunc(size_t target)
{
    return findJNITraceEntry(target);
}

/* 查找目标地址对应的libc trace回调 */
static TraceFunc* findLibcTraceFunc(size_t target)
{
    if(_g_libc_trace == nullptr)
    {
        return nullptr;
    }
    auto it = _g_libc_trace->map.find(target);
    return it == _g_libc_trace->map.end() ? nullptr : it->second;
}

/* 带长度保护的格式化追加 */
static int appf(char* out, size_t size, int off, const char* fmt, ...)
{
    if (off < 0) off = 0;
    if ((size_t)off >= size) return (int)size - 1;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + off, size - off, fmt, ap);
    va_end(ap);
    if (n < 0) return off;
    return (off + n < (int)size) ? off + n : (int)size - 1;
}

/*! 取模块短名: /apex/com.android.art/lib64/libart.so -> libart.so */
static void moduleShortName(const char* path, char* buf, size_t size)
{
    if (path == nullptr || path[0] == '\0')
    {
        snprintf(buf, size, "unknown");
        return;
    }
    const char* p = strrchr(path, '/');
    snprintf(buf, size, "%s", p != nullptr ? p + 1 : path);
}

/*
 * 是不是 ART 相关模块。
 * QBDI 的"重放"上下文里执行 ART 代码是危险的（JNI 引用/ArtMethod 解引用会崩），
 * 而 libc / 其它普通 so 只是普通 native 代码，可以照常执行。
 */
static bool isArtModuleName(const char* path)
{
    if (path == nullptr)
    {
        return false;
    }
    return strstr(path, "libart.so") != nullptr ||
           strstr(path, "libartbase") != nullptr ||
           strstr(path, "libnativehelper") != nullptr ||
           strstr(path, "libopenjdkjvm") != nullptr;
}

/* 调用信息头部:
 *  - 已hook的函数: "Call addr: 0x地址 [模块!偏移] "（不带换行，紧接着由回调输出 name(args)）
 *  - 未hook的函数: "Call addr: 0x地址 [模块!偏移]"（带换行）
 */

/*
 * 目标地址 -> 模块信息缓存（thread_local）。
 * 已hook的libc函数(memcpy/malloc...)调用量可能很大，每个调用都dladdr会很慢；
 * 目标地址集合很小，缓存后只做哈希查找。
 */
struct CallHeadModInfo
{
    bool ok;
    uint64_t off;
    char mod[128];
};

static void lookupTargetModule(uint64_t target, bool &ok, char *mod, size_t modSize, uint64_t &off)
{
    static thread_local unordered_map<uint64_t, CallHeadModInfo> cache;
    auto it = cache.find(target);
    if (it == cache.end())
    {
        CallHeadModInfo info{};
        Dl_info dl_info{};
        info.ok = (target != 0 && dladdr((void*)target, &dl_info) != 0 &&
                   dl_info.dli_fname != nullptr);
        if (info.ok)
        {
            moduleShortName(dl_info.dli_fname, info.mod, sizeof(info.mod));
            info.off = target - (uint64_t)dl_info.dli_fbase;
        }
        it = cache.emplace(target, info).first;
    }
    ok = it->second.ok;
    off = it->second.off;
    snprintf(mod, modSize, "%s", ok ? it->second.mod : "unknown");
}

static int buildCallHead(char* out, size_t size, uint64_t target, const char* hookName)
{
    int off = 0;
    bool ok = false;
    uint64_t targetModOff = 0;
    char mod[128] = "unknown";
    lookupTargetModule(target, ok, mod, sizeof(mod), targetModOff);

    //已hook和未hook的调用都先打印十六进制地址+模块内偏移，便于和指令行/IDA对照
    off = appf(out, size, off, "Call addr: 0x%" PRIx64, target);
    if (ok)
    {
        off = appf(out, size, off, " [%s!0x%" PRIx64 "]", mod, targetModOff);
    }
    else
    {
        off = appf(out, size, off, " [unknown]");
    }

    if (hookName != nullptr)
    {
        //已hook的函数: 地址之后留一个空格，回调紧接着输出 name(args)
        off = appf(out, size, off, " ");
        return off;
    }
    off = appf(out, size, off, "\n");
    return off;
}

/* 反汇编缓存：按线程隔离，避免多线程 trace 同时 emplace 触发 unordered_map 竞争 */
static thread_local unordered_map<uint32_t,char*> disassemblecache;

// 显示指令执行前的寄存器状态
QBDI::VMAction showPreInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    auto thiz = (class vm *)data;
    /* 本条指令是否是"进ART/未知模块"的调用/跳转且开启了 bit4(TRACE_CFG_STOP_BEFORE_ART) */
    bool stopAfterThis = false;

    //上一条指令的信息全部拿到了，写入
    flushPending(vm, gprState);

    /*
     * 指令分析只能取一次，三种信息一起要。
     * QBDI 把分析结果缓存在 VM 内部的同一份 InstAnalysis 上：
     * 再调用一次 getInstAnalysis(别的类型) 会把上一次返回结构里的
     * operands / disassembly 覆盖掉，原来那个指针就失效了。
     * 旧代码先要 INSTRUCTION|OPERANDS、再要 DISASSEMBLY，然后继续读
     * instAnalysis->operands[i].regName，读到的是野指针 ——
     * 表现就是 "access violation accessing 0x7040xxxx" 这种随机堆地址崩溃。
     */
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_OPERANDS | QBDI::ANALYSIS_DISASSEMBLY);
    if (instAnalysis == nullptr || instAnalysis->address == 0)
    {
        LOGE("preinst: getInstAnalysis fail");
        return QBDI::VMAction::CONTINUE;
    }
    uint32_t bytecode = *(uint32_t*)instAnalysis->address;

    //用缓存的反汇编，减低开销
    char* disasm;
    auto it = disassemblecache.find(bytecode);
    if (it != disassemblecache.end()) {
        disasm = it->second;
    } else {
        const char *fullDisasm = instAnalysis->disassembly != nullptr ? instAnalysis->disassembly : "";
        size_t len = strlen(fullDisasm) + 1;
        disasm = (char*)malloc(len);
        memcpy(disasm, fullDisasm, len);
        disassemblecache.emplace(bytecode, disasm);
    }

    // 自定义QBDI hook（按模块内偏移匹配）
    checkAndCallHook(vm,gprState,(instAnalysis->address-thiz->base),(lastAddr - thiz->base));

    pending.numRegs = 0;
    pending.memLen = 0;
    pending.syscallLen = 0;
    pending.callHeadLen = 0;
    pending.deferredCb = nullptr;
    pending.deferredCbName = nullptr;
    pending.libcHooked = false;
    pending.hasSnapshot = false;

    // 收集寄存器: 写寄存器输出 before -> after, 读寄存器输出当前值
    for (int i = 0; i < instAnalysis->numOperands; ++i)
    {
        auto& op = instAnalysis->operands[i];
        if (op.type != OPERAND_GPR || op.regCtxIdx < 0 || op.regName == nullptr)
        {
            continue;
        }
        bool write = (op.regAccess == REGISTER_WRITE || op.regAccess == REGISTER_READ_WRITE);
        bool read = (op.regAccess == REGISTER_READ || op.regAccess == REGISTER_READ_WRITE);
        if (!write && !read)
        {
            continue;
        }
        uint64_t value = QBDI_GPR_GET(gprState, op.regCtxIdx);
        //xzr/wzr是零寄存器，QBDI给出的序号是NZCV，这里强制为0
        if (strcasecmp(op.regName, "XZR") == 0 || strcasecmp(op.regName, "WZR") == 0)
        {
            value = 0;
        }
        appendRegRec(op.regName, op.regCtxIdx, value, write, 0);
    }

    // 分支/调用指令: 目标地址、符号、返回地址
    const char* mnemonic = instAnalysis->mnemonic != nullptr ? instAnalysis->mnemonic : "";
    bool isBl  = (strcasecmp(mnemonic, "bl") == 0);
    bool isBr  = (strcasecmp(mnemonic, "br") == 0);
    bool isCall = isBl || (strcasecmp(mnemonic, "blr") == 0);

    if (isCall || isBr)
    {
        uint64_t target = 0;
        bool hasTarget = false;
        for (int i = 0; i < instAnalysis->numOperands && !hasTarget; ++i)
        {
            auto& op = instAnalysis->operands[i];
            if (op.type == OPERAND_GPR && op.regCtxIdx >= 0 &&
                (op.regAccess == REGISTER_READ || op.regAccess == REGISTER_READ_WRITE))
            {
                //blr/br的目标在寄存器里
                target = QBDI_GPR_GET(gprState, op.regCtxIdx);
                hasTarget = true;
            }
            else if (isBl && op.type == OPERAND_IMM)
            {
                //bl是直接调用: QBDI给出的立即数是指令条数(imm26)，需要符号扩展后还原成绝对地址
                int64_t imm26 = ((int64_t)((uint64_t)op.value << 38)) >> 38;
                target = (uint64_t)((int64_t)instAnalysis->address + (imm26 << 2));
                hasTarget = true;
            }
        }

        if (isCall)
        {
            //调用约定: SP为调用时的栈指针, LR写入返回地址
            appendRegRec("SP", QBDI::REG_SP, QBDI_GPR_GET(gprState, QBDI::REG_SP), false, 0);
            appendRegRec("LR", QBDI::REG_LR, QBDI_GPR_GET(gprState, QBDI::REG_LR), true,
                         (uint64_t)instAnalysis->address + instAnalysis->instSize);
        }

        if (hasTarget)
        {
            //jni/libc的trace回调延迟到调用行之后执行，保证 "Call addr/参数/返回值" 的顺序
            //bl直接调用和blr/br间接调用都可能是已注册的jni/libc函数，统一查两张表
            //setBufferSize 的 bit1/bit3 分别控制 jni/libc trace 是否生效
            TraceFunc* traceFunc = nullptr;
            bool isLibc = false;
            if (is_jni_trace_enabled())
            {
                traceFunc = findJniTraceFunc(target);
            }
            if (traceFunc == nullptr && is_libc_trace_enabled())
            {
                traceFunc = findLibcTraceFunc(target);
                isLibc = (traceFunc != nullptr);
            }
            TraceCallBack cb = traceFunc != nullptr ? traceFunc->callback : nullptr;

            //只对"跨模块"的调用（进入系统库/其他so）或已注册的jni/libc函数打印Call信息；
            //模块内部的bl/blr（含PLT前的本地跳转）只保留指令行，避免刷屏和无意义的[unknown]
            Dl_info targetInfo{};
            bool resolved = (target != 0 && dladdr((void*)target, &targetInfo) != 0 &&
                             targetInfo.dli_fbase != nullptr);
            bool outsideModule = resolved &&
                                 (reinterpret_cast<uint64_t>(targetInfo.dli_fbase) != (uint64_t)thiz->base);
            /*
             * 目标是否"离开了被trace模块"：
             *  - dladdr 能认出来且不是本模块      -> 跨模块
             *  - dladdr 认不出来(匿名映射/JIT/PLT) -> 再用模块 [start,end) 判一次
             */
            bool inModuleRange = (_g_trace_data->end > _g_trace_data->start) &&
                                 target >= _g_trace_data->start && target < _g_trace_data->end;
            bool leavesModule = outsideModule || (target == 0) || (!resolved && !inModuleRange);

            char targetMod[128] = "unknown";
            uint64_t targetModOff = 0;
            if (resolved)
            {
                if (targetInfo.dli_fname != nullptr)
                {
                    moduleShortName(targetInfo.dli_fname, targetMod, sizeof(targetMod));
                }
                targetModOff = target - (uint64_t)targetInfo.dli_fbase;
            }

            /*
             * 安全模式(bit4)：进 ART / 未知模块之前停 trace。
             *
             * 只拦这类目标的原因：
             *  - trace_call() 是"重放"：只有 x0~x7 是真的，栈是 sp-0x4000 挪过的，
             *    x8~x28 也不是调用现场的值。加固so的VM在这份上下文里调 JNI 时，
             *    ART 会用 VM 缓存里的 jmethodID/jobject 去解引用，落到 linear alloc 的空洞上
             *    直接 SIGSEGV —— 就是 "Error: access violation accessing 0x7040xxxx"。
             *  - libc / 其它普通 so 是纯 native 代码，不碰 JNI 引用，照常执行没问题，
             *    所以 malloc/memcpy/mmap 这些不会被误停，日志能多走一段。
             * 停止后由 frida 把真实函数原生再跑一遍，保证 app 行为不变。
             */
            bool stopHere = false;
            if ((bufstate & TRACE_CFG_STOP_BEFORE_ART) != 0 && leavesModule)
            {
                /*
                 * 只拦两类目标，别的一律让它跑：
                 *   1) 已注册的 JNI 函数（进 libart 解引用 jmethodID/jobject，必崩）
                 *   2) libart/libnativehelper 里的代码
                 * 目标解析不出模块(dladdr 失败，例如 shadowhook/dobby 的 trampoline 在匿名可执行页)
                 * 时**不停**，否则会在第一条外部调用处就停住，日志只有几十行。
                 */
                bool jniCall = (cb != nullptr && !isLibc);
                bool artTarget = (target == 0) || isArtModuleName(targetMod);
                if (jniCall || artTarget)
                {
                    char why[80] = "";
                    if (target == 0) {
                        snprintf(why, sizeof(why), "null target");
                    } else if (jniCall) {
                        snprintf(why, sizeof(why), "JNI %s", traceFunc->name != nullptr ? traceFunc->name : "?");
                    } else {
                        snprintf(why, sizeof(why), "ART");
                    }
                    pending.syscallLen = appf(pending.syscallInfo, sizeof(pending.syscallInfo), 0,
                                              "  [STOP] %s %s 0x%" PRIx64 " [%s!0x%" PRIx64
                                              "], stop before entering ART (bit4)\n",
                                              isCall ? "call" : "jump", why, target, targetMod, targetModOff);
                    g_stopped_at_cross = true;
                    stopHere = true;
                }
            }

            if (stopHere)
            {
                stopAfterThis = true;
            }
            else
            {
                if (outsideModule || cb != nullptr)
                {
                    if (cb != nullptr && !isLibc)
                    {
                        //JNI函数不打印 "Call addr:"，直接由回调输出 [JNI] 调用行/原型/返回值
                        pending.callHeadLen = 0;
                    }
                    else
                    {
                        //已hook的libc函数只打印 "Call addr: "，函数名和参数由回调紧接着输出
                        pending.callHeadLen = buildCallHead(pending.callHead, sizeof(pending.callHead),
                                                            target, cb != nullptr ? traceFunc->name : nullptr);
                    }
                }
                if (cb != nullptr)
                {
                    pending.deferredCb = cb;
                    pending.deferredCbName = traceFunc->name;
                    pending.libcHooked = isLibc;
                    pending.snapshot = *gprState;
                    pending.hasSnapshot = true;
                }
            }
        }
    }

    // 指令行: 绝对地址 \t 模块内偏移 \t\t 助记符 \t 操作数
    size_t mnemLen = strcspn(disasm, " \t");
    pending.lineLen = appf(pending.line, sizeof(pending.line), 0,
                           "0x%" PRIx64 "\t0x%" PRIx64 "\t\t%.*s\t%s\t",
                           (uint64_t)instAnalysis->address,
                           (uint64_t)(instAnalysis->address - thiz->base),
                           (int)mnemLen, disasm, disasm + mnemLen);

    pending.valid = true;

    logger* cur = currentLogger();
    if(cur != nullptr && sdslen(cur->buf) > bufsize)
    {
        writelog();
    }
    lastAddr = instAnalysis->address;
    if (stopAfterThis)
    {
        /*
         * 主动停止：本条指令是跨模块调用/跳转，bit4 要求不把它搬进 QBDI 执行。
         * 注意这里 return STOP 后 QBDI 的 run/call 提前返回，
         * trace_call() 会在 callA() 之后把 pending 这条指令刷完并落盘。
         */
        LOGE("preinst: stop before entering ART/unknown 0x%" PRIx64 " (TRACE_CFG_STOP_BEFORE_ART)", (uint64_t)instAnalysis->address);
        return QBDI::VMAction::STOP;
    }
    return QBDI::VMAction::CONTINUE;
}

// 显示指令执行后的寄存器状态 打印字符串 hexdump
QBDI::VMAction showPostInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    auto thiz = (class vm *)data;

    // 获取当前指令的分析信息，包括指令、符号、操作数等
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_OPERANDS);

    std::stringstream output;
    std::stringstream regOutput;

    // 遍历操作数并记录写入的寄存器状态
    for (int i = 0; i < instAnalysis->numOperands; ++i)
    {
        auto op = instAnalysis->operands[i];
        if (op.regAccess == REGISTER_WRITE || op.regAccess == REGISTER_READ_WRITE)
        {
            if (op.regCtxIdx != -1 && op.type == OPERAND_GPR)
            {
                // 获取寄存器值
                uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);
                // 输出寄存器名称和值
                output << op.regName << "=0x" << std::hex << regValue << " ";
                output.flush();
            }
        }
    }

    // 如果有写入的寄存器信息，格式化输出；否则，仅换行
    if (!output.str().empty())
    {
        appendlog("\t => [");
        appendlog(output.str().c_str());
        appendlog("]");
        appendlogendl();
    }
    else
    {
        appendlogendl();
        appendlog(regOutput.str().c_str());
    }
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction showMemoryAccess(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    const auto& accesses = vm->getInstMemoryAccess();   // 只调一次
    for (const auto &acc : accesses)
    {
        const char* tag = (acc.type == MEMORY_READ)  ? "mem[r]"
                                                     : (acc.type == MEMORY_WRITE) ? "mem[w]"
                                                                                  : "mem[rw]";
        pending.memLen += snprintf(pending.memInfo + pending.memLen,
                                   sizeof(pending.memInfo) - pending.memLen,
                                   "%s: 0x%" PRIx64 " size: %u value: 0x%" PRIx64 "\n",
                                   tag,
                                   (uint64_t)acc.accessAddress,
                                   (unsigned)acc.size,
                                   (uint64_t)acc.value);
        if (pending.memLen >= (int)sizeof(pending.memInfo)) {
            pending.memLen = sizeof(pending.memInfo) - 1;
            break;
        }
    }
    return QBDI::VMAction::CONTINUE;
}

/*
 * syscall trace: AArch64上系统调用统一走 svc 指令, x8=系统调用号, x0~x5=参数。
 * 这里把调用号/参数记到pending里，由flushPending紧跟在svc指令行之后输出，
 * 保证 "指令行 -> [SYSCALL] ... -> 返回值(x0在指令后变化)" 的顺序。
 */
QBDI::VMAction showSyscall(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
    if (instAnalysis == nullptr || instAnalysis->mnemonic == nullptr ||
        strcasecmp(instAnalysis->mnemonic, "svc") != 0 || !pending.valid)
    {
        return QBDI::VMAction::CONTINUE;
    }
    uint64_t nr = QBDI_GPR_GET(gprState, 8);
    pending.syscallLen = appf(pending.syscallInfo, sizeof(pending.syscallInfo), 0,
                              "  [SYSCALL] nr=%lu(0x%lx) x0=0x%lx x1=0x%lx x2=0x%lx x3=0x%lx x4=0x%lx x5=0x%lx\n",
                              nr, nr,
                              QBDI_GPR_GET(gprState, 0),
                              QBDI_GPR_GET(gprState, 1),
                              QBDI_GPR_GET(gprState, 2),
                              QBDI_GPR_GET(gprState, 3),
                              QBDI_GPR_GET(gprState, 4),
                              QBDI_GPR_GET(gprState, 5));
    return QBDI::VMAction::CONTINUE;
}

QBDI::VM vm::init(size_t base,size_t target)
{
    uint32_t cid;
    QBDI::GPRState *state;
    QBDI::VM qvm{};
    state = qvm.getGPRState();
    loadMemoryRanges();
    if(state == nullptr)
    {
        LOGE("init vm fail: gpr state is null");
        return qvm;
    }
    qvm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);

    //指令前hook
    cid = qvm.addCodeCB(QBDI::PREINST, showPreInstruction, this);
    if(cid == QBDI::INVALID_EVENTID)
    {
        LOGE("init vm fail: add preinst callback fail");
    }

    //指令后hook
    //cid = qvm.addCodeCB(QBDI::POSTINST, showPostInstruction, this);
    //assert(cid != QBDI::INVALID_EVENTID);

    //syscall trace: 只在 svc 指令上记录系统调用号(x8)和参数(x0~x5)
    cid = qvm.addCodeCB(QBDI::PREINST, showSyscall, this);
    if(cid == QBDI::INVALID_EVENTID)
    {
        LOGE("init vm fail: add syscall callback fail");
    }

    //读写trace
    cid = qvm.addMemAccessCB(MEMORY_READ_WRITE, showMemoryAccess, this);
    if(cid == QBDI::INVALID_EVENTID)
    {
        LOGE("init vm fail: add mem access callback fail");
    }

    bool ret = qvm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(target));
    if(!ret)
    {
        //部分被加固/重命名的so QBDI解析不到模块信息，退化到只instrument函数所在的执行段
        size_t exec_start = 0;
        size_t exec_end = 0;
        if(getExecRangeOfAddr(target,exec_start,exec_end))
        {
            LOGE("addInstrumentedModuleFromAddr fail, instrument exec segment:[%p-%p]",
                 (void*)exec_start,(void*)exec_end);
            qvm.addInstrumentedRange(reinterpret_cast<QBDI::rword>(exec_start),
                                     reinterpret_cast<QBDI::rword>(exec_end));
            ret = true;
        }
    }
    if(!ret)
    {
        LOGE("init vm fail");
    }
    else
    {
        LOGE("init vm success");
    }
    this->base = base;
    return qvm;
}