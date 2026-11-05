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
g_trace_data* _g_trace_data = &g_trace_data_storage;
size_t g_deferred_call_retval = 0;
const char* g_deferred_call_name = nullptr;
void* g_deferred_call_env = nullptr;
int bufsize = 0x1000000;
int bufstate = 0;
bool debugInsn = false;


void setBufferSize(int size)
{
    /*
     * 32位打包值:
     *   bit7 .. bit0   : 配置状态，按 initTraceEnv 里 enable_* 的调用顺序从bit0开始:
     *                    bit0 enableDebugInsn        (逐指令日志)
     *                    bit1 enable_jni_trace_debug (jni trace)
     *                    bit2 enable_jni_resolve     (obj类名/method名称解析)
     *                    bit3 enable_libc_trace_debug(libc trace)
     *   bit31.. bit8   : 累计写盘阈值，等价字节数 = 值 & 0xFFFFFF00
     * 例如:
     *   0x10000000 = 256MB, state=0x00
     *   0x1000000A = 256MB, state=0x0A (jni trace + libc trace 开启)
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
    enableDebugInsn((bufstate & (1 << 0)) != 0);
    enable_jni_trace_debug((bufstate & (1 << 1)) != 0);
    enable_jni_resolve((bufstate & (1 << 2)) != 0);
    enable_libc_trace_debug((bufstate & (1 << 3)) != 0);

    LOGE("setBufferSize: raw=0x%x, state=0x%x, flushThreshold=%u bytes(%u MB)",
         value, (unsigned)bufstate, bytes, bytes >> 20);
    LOGE("trace config: debugInsn=%d, jniTrace=%d, jniResolve=%d, libcTrace=%d",
         (bufstate & (1 << 0)) ? 1 : 0, (bufstate & (1 << 1)) ? 1 : 0,
         (bufstate & (1 << 2)) ? 1 : 0, (bufstate & (1 << 3)) ? 1 : 0);
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
    char callHead[512];      // Call addr（已hook函数只输出 "Call addr: "，参数行由回调补全）
    int  callHeadLen = 0;
    TraceCallBack deferredCb = nullptr;  // jni/libc trace回调，延迟到调用行之后执行
    const char* deferredCbName = nullptr; // 对应函数名
    bool libcHooked = false;             // 已注册的是libc函数，需要额外输出返回值
    QBDI::GPRState snapshot{};           // 调用前的寄存器快照
    bool hasSnapshot = false;
};

static PendingInst pending;

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

// trace使用全局的logger/pending/disassemble缓存，这里串行化，
// 同时禁止同一线程重入，避免trace状态被破坏
static std::mutex g_trace_mutex;
static thread_local bool g_tracing = false;

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
    if (g_tracing)
    {
        LOGE("trace_call: trace is already running in current thread, skip");
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

    std::lock_guard<std::mutex> lock(g_trace_mutex);
    g_tracing = true;

    _g_trace_data->base = soinfo.start;
    _g_trace_data->start = soinfo.start;
    _g_trace_data->end = soinfo.end;

    //先创建日志文件：这样即使后面QBDI初始化/执行时崩溃，也能通过日志文件是否存在判断执行到了哪一步
    initLoggerWithPath(log_path,function_address);
    LOGE("start trace:%p,module:[%p-%p],log:%s", func_addr,
         (void *)_g_trace_data->start, (void *)_g_trace_data->end,
         _logger->logfile.c_str());
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
        g_tracing = false;
        return 0;
    }
    vm_->base = _g_trace_data->base;
    //在当前栈上开辟栈，不使用allocateVirtualStack，防止libart中Thread crash
    size_t sp = get_current_sp();
    size_t stack_size = 0x4000;
    QBDI_GPR_SET(qbdi_state, QBDI::REG_SP, sp - stack_size);
    QBDI_GPR_SET(qbdi_state, QBDI::REG_BP, QBDI_GPR_GET(qbdi_state, QBDI::REG_SP));
    QBDI::rword qbdi_retval = 0;
    LOGE("trace begin");
    //参数按AAPCS64约定通过x0~x7传入
    bool qbdi_success = qvm.callA(&qbdi_retval, (QBDI::rword)function_address,
                                  (uint32_t)arg_num,
                                  reinterpret_cast<const QBDI::rword *>(args));
    LOGE("trace end");
    flushPending(nullptr, qbdi_state);
    writelog();
    if (qbdi_success) {
        LOGE("trace completed successfully %s",_logger->logfile.c_str());
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
    g_tracing = false;
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

/* 查找目标地址对应的jni trace回调 */
static TraceFunc* findJniTraceFunc(size_t target)
{
    if(_g_jni_trace == nullptr)
    {
        return nullptr;
    }
    auto it = _g_jni_trace->map.find(target);
    return it == _g_jni_trace->map.end() ? nullptr : it->second;
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

/* 取模块短名: /apex/com.android.art/lib64/libart.so -> libart.so */
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

/* 调用信息头部:
 *  - 已hook的函数: "Call addr: "（不带换行，紧接着由回调输出 name(args)）
 *  - 未hook的函数: "Call addr: 0x地址 [模块!偏移]"
 */
static int buildCallHead(char* out, size_t size, uint64_t target, const char* hookName)
{
    int off = 0;
    if (hookName != nullptr)
    {
        return appf(out, size, off, "Call addr: ");
    }

    Dl_info info{};
    bool ok = (target != 0 && dladdr((void*)target, &info) != 0 && info.dli_fname != nullptr);
    char mod[128] = "unknown";
    if (ok)
    {
        moduleShortName(info.dli_fname, mod, sizeof(mod));
    }

    off = appf(out, size, off, "Call addr: 0x%" PRIx64, target);
    if (ok)
    {
        //未hook的跨模块调用统一显示 [模块名!模块内偏移]
        off = appf(out, size, off, " [%s!0x%" PRIx64 "]", mod, target - (uint64_t)info.dli_fbase);
    }
    else
    {
        off = appf(out, size, off, " [unknown]");
    }
    off = appf(out, size, off, "\n");
    return off;
}

static size_t lastAddr = 0;

static unordered_map<uint32_t,char*> disassemblecache;

// 显示指令执行前的寄存器状态
QBDI::VMAction showPreInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    auto thiz = (class vm *)data;

    //上一条指令的信息全部拿到了，写入
    flushPending(vm, gprState);

    // 获取当前指令的分析信息
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION  | QBDI::ANALYSIS_OPERANDS);
    uint32_t bytecode = *(uint32_t*)instAnalysis->address;

    //用缓存的反汇编，减低开销
    char* disasm;
    auto it = disassemblecache.find(bytecode);
    if (it != disassemblecache.end()) {
        disasm = it->second;
    } else {
        const QBDI::InstAnalysis *full = vm->getInstAnalysis(QBDI::ANALYSIS_DISASSEMBLY);
        size_t len = strlen(full->disassembly) + 1;
        disasm = (char*)malloc(len);
        memcpy(disasm, full->disassembly, len);
        disassemblecache.emplace(bytecode, disasm);
    }

    // 自定义QBDI hook（按模块内偏移匹配）
    checkAndCallHook(vm,gprState,(instAnalysis->address-thiz->base),(lastAddr - thiz->base));

    pending.numRegs = 0;
    pending.memLen = 0;
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

    // 指令行: 绝对地址 \t 模块内偏移 \t\t 助记符 \t 操作数
    size_t mnemLen = strcspn(disasm, " \t");
    pending.lineLen = appf(pending.line, sizeof(pending.line), 0,
                           "0x%" PRIx64 "\t0x%" PRIx64 "\t\t%.*s\t%s\t",
                           (uint64_t)instAnalysis->address,
                           (uint64_t)(instAnalysis->address - thiz->base),
                           (int)mnemLen, disasm, disasm + mnemLen);

    pending.valid = true;

    if(sdslen(_logger->buf) > bufsize)
    {
        writelog();
    }
    lastAddr = instAnalysis->address;
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

QBDI::VMAction showSyscall(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
    if (instAnalysis->mnemonic && strcasecmp(instAnalysis->mnemonic, "svc") == 0)
    {

    }
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

    //TODO:syscall trace
    //cid = qvm.addCodeCB(QBDI::PREINST, showSyscall, this);
    //assert(cid != QBDI::INVALID_EVENTID);

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