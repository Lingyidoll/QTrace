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
int bufsize = 0x1000000;
bool debugInsn = false;


void setBufferSize(int size)
{
    bufsize = size;
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
    char callHead[512];      // Call addr / Entering system lib
    int  callHeadLen = 0;
    char callTail[256];      // Return to
    int  callTailLen = 0;
    TraceCallBack deferredCb = nullptr;  // jni/libc trace回调，延迟到调用行之后执行
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
    // jni/libc trace回调放在调用行之后执行，保证 "Call addr / 参数 / Return to" 的顺序
    if (pending.deferredCb != nullptr) {
        // 回调在调用返回之后执行，x0此时是调用返回值
        g_deferred_call_retval = (size_t)QBDI_GPR_GET(gprState, QBDI::REG_RETURN);
        pending.deferredCb(vm, pending.hasSnapshot ? &pending.snapshot : gprState);
    }
    if (pending.callTailLen > 0) {
        appendlog_n(pending.callTail, pending.callTailLen);
        appendlogendl();
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
static TraceCallBack findJniCallback(size_t target)
{
    if(_g_jni_trace == nullptr)
    {
        return nullptr;
    }
    auto it = _g_jni_trace->map.find(target);
    return it == _g_jni_trace->map.end() ? nullptr : it->second->callback;
}

/* 查找目标地址对应的libc trace回调 */
static TraceCallBack findLibcCallback(size_t target)
{
    if(_g_libc_trace == nullptr)
    {
        return nullptr;
    }
    auto it = _g_libc_trace->map.find(target);
    return it == _g_libc_trace->map.end() ? nullptr : it->second->callback;
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

/* 是否是系统库 */
static bool isSystemLibPath(const char* path)
{
    if (path == nullptr)
    {
        return false;
    }
    static const char* kSystemPrefix[] = {"/system/", "/apex/", "/vendor/", "/product/", "/odm/"};
    for (size_t i = 0; i < sizeof(kSystemPrefix) / sizeof(kSystemPrefix[0]); ++i)
    {
        if (strncmp(path, kSystemPrefix[i], strlen(kSystemPrefix[i])) == 0)
        {
            return true;
        }
    }
    return false;
}

/* 调用信息头部: Call addr + 符号 + 是否进入系统库 */
static int buildCallHead(char* out, size_t size, uint64_t target)
{
    int off = 0;
    Dl_info info{};
    bool ok = (target != 0 && dladdr((void*)target, &info) != 0 && info.dli_fname != nullptr);
    char mod[128] = "unknown";
    if (ok)
    {
        moduleShortName(info.dli_fname, mod, sizeof(mod));
    }

    off = appf(out, size, off, "Call addr: 0x%" PRIx64, target);
    if (ok && info.dli_sname != nullptr)
    {
        off = appf(out, size, off, " %s", info.dli_sname);
    }
    else if (ok)
    {
        off = appf(out, size, off, " [%s!0x%" PRIx64 "]", mod, target - (uint64_t)info.dli_fbase);
    }
    else
    {
        off = appf(out, size, off, " [unknown]");
    }
    off = appf(out, size, off, "\n");
    if (ok && isSystemLibPath(info.dli_fname))
    {
        off = appf(out, size, off, "  -> Entering system lib: %s\n", mod);
    }
    return off;
}

/* 调用信息尾部: 返回到哪里 */
static int buildCallTail(char* out, size_t size, QBDI::GPRState* gprState,
                         uint64_t address, uint32_t instSize, bool isCall)
{
    // bl/blr的返回地址是下一条指令; br是跳转前的LR
    uint64_t retAddr = isCall ? (address + instSize) : QBDI_GPR_GET(gprState, QBDI::REG_LR);
    char mod[128] = "unknown";
    Dl_info info{};
    if (retAddr != 0 && dladdr((void*)retAddr, &info) != 0 && info.dli_fname != nullptr)
    {
        moduleShortName(info.dli_fname, mod, sizeof(mod));
    }
    return appf(out, size, 0, "  <- Return to: 0x%" PRIx64 " (%s)\n", retAddr, mod);
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
    pending.callTailLen = 0;
    pending.deferredCb = nullptr;
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
    bool isBlr = (strcasecmp(mnemonic, "blr") == 0);
    bool isBr  = (strcasecmp(mnemonic, "br") == 0);
    bool isCall = isBl || isBlr;

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
            //jni/libc的trace回调延迟到调用行之后执行，保证 "Call addr/参数/Return to" 的顺序
            TraceCallBack cb = nullptr;
            if (isBlr)
            {
                cb = findJniCallback(target);
            }
            else if (isBr)
            {
                cb = findLibcCallback(target);
                if (cb == nullptr)
                {
                    cb = findJniCallback(target);
                }
            }

            //只对"跨模块"的调用（进入系统库/其他so）或已注册的jni/libc函数打印Call信息；
            //模块内部的bl/blr（含PLT前的本地跳转）只保留指令行，避免刷屏和无意义的[unknown]
            Dl_info targetInfo{};
            bool resolved = (target != 0 && dladdr((void*)target, &targetInfo) != 0 &&
                             targetInfo.dli_fbase != nullptr);
            bool outsideModule = resolved &&
                                 (reinterpret_cast<uint64_t>(targetInfo.dli_fbase) != (uint64_t)thiz->base);

            if (outsideModule || cb != nullptr)
            {
                pending.callHeadLen = buildCallHead(pending.callHead, sizeof(pending.callHead), target);
                pending.callTailLen = buildCallTail(pending.callTail, sizeof(pending.callTail),
                                                    gprState, instAnalysis->address,
                                                    instAnalysis->instSize, isCall);
            }
            if (cb != nullptr)
            {
                pending.deferredCb = cb;
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