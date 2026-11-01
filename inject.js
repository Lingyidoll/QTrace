// QTrace frida 脚本
//
// 使用方式：
//   frida -U -f com.shizhuang.duapp -l inject.js
//
// 说明：
//   注入 libnativelib.so 之后，直接调用它导出的 lingyi_vm_call
//   即可对目标函数做 QBDI trace，不再依赖 shadowhook inline hook。
//
//   size_t lingyi_vm_call(void *func_addr, size_t *args, uint32_t arg_num,
//                         const char *log_path, uint32_t flags);

var TRACE_SO_PATH = "/data/local/tmp/libnativelib.so"; // QTrace 模块
var TARGET_SO = "libGameVMP.so";                       // 需要 trace 的 so
var TARGET_OFFSET = 0xe7a8;                            // 需要 trace 的函数偏移
var APP_NAME = "com.shizhuang.duapp";                  // 日志写到该应用私有目录

var vmCall = null;
var targetHooked = false;

/* 兼容不同 frida 版本的导出符号查找 */
function findGlobalExport(name) {
    if (typeof Module.findGlobalExportByName === 'function') {
        return Module.findGlobalExportByName(name);
    }
    return Module.findExportByName(null, name);
}

function findModuleExport(moduleName, exportName) {
    var mod = Process.findModuleByName(moduleName);
    if (mod === null) {
        return null;
    }
    if (typeof mod.findExportByName === 'function') {
        return mod.findExportByName(exportName);
    }
    return mod.getExportByName(exportName);
}

/* 把 JS 参数打包成一段连续的指针数组，每个元素占一个寄存器槽位 */
function prepareArgs(args) {
    if (args === undefined || args === null || !Array.isArray(args)) {
        args = [];
    }
    var argNum = args.length;
    var argsPtr = Memory.alloc(Process.pointerSize * argNum);

    for (var i = 0; i < argNum; i++) {
        var arg = args[i];
        var argPtr;
        if (!arg) {
            arg = 0;
        }
        if (arg instanceof NativePointer) {
            // 已经是 NativePointer，直接使用
            argPtr = arg;
        } else if (typeof arg === 'number') {
            // 数字直接转换成指针值
            argPtr = ptr(arg);
        } else if (typeof arg === 'string') {
            // 字符串分配内存，参数里传指针
            argPtr = Memory.allocUtf8String(arg);
        } else if (typeof arg === 'object' && arg.hasOwnProperty('handle')) {
            // 带有 handle 属性的对象（如 JNIEnv / JavaVM）
            argPtr = arg.handle;
        } else if (typeof arg === 'object' && arg instanceof ArrayBuffer) {
            // 二进制数据，分配内存并写入
            var dataPtr = Memory.alloc(arg.byteLength);
            Memory.writeByteArray(dataPtr, arg);
            argPtr = dataPtr;
        } else {
            console.error('Unsupported argument type at index ' + i + ':', typeof arg);
            throw new TypeError('Unsupported argument type at index ' + i + ': ' + typeof arg);
        }
        ptr(argsPtr.add(i * Process.pointerSize)).writePointer(argPtr);
    }

    return {
        argsPtr: argsPtr,
        argNum: argNum
    };
}

/* 获取 libnativelib.so 导出的 lingyi_vm_call */
function getVmCall() {
    if (vmCall !== null) {
        return vmCall;
    }
    var addr = findGlobalExport("lingyi_vm_call");
    if (addr === null) {
        addr = findModuleExport("libnativelib.so", "lingyi_vm_call");
    }
    if (addr === null) {
        throw new Error("未找到导出符号 lingyi_vm_call，请先注入 " + TRACE_SO_PATH);
    }
    console.log("[QTrace] lingyi_vm_call @ " + addr);
    vmCall = new NativeFunction(addr, 'pointer',
        ['pointer', 'pointer', 'uint32', 'pointer', 'uint32']);
    return vmCall;
}

var vmInit = null;

/* 获取 libnativelib.so 导出的 lingyi_vm_init（只初始化trace环境，用于排查） */
function getVmInit() {
    if (vmInit !== null) {
        return vmInit;
    }
    var addr = findGlobalExport("lingyi_vm_init");
    if (addr === null) {
        addr = findModuleExport("libnativelib.so", "lingyi_vm_init");
    }
    if (addr === null) {
        return null;
    }
    vmInit = new NativeFunction(addr, 'int', []);
    return vmInit;
}

/* 把 JNIEnv 直接传给 QTrace：部分机型上 QTrace 自己找不到 JNI_GetCreatedJavaVMs，JNI trace 会失效 */
function setJniEnv(envPtr) {
    var addr = findGlobalExport("lingyi_vm_set_jnienv");
    if (addr === null) {
        addr = findModuleExport("libnativelib.so", "lingyi_vm_set_jnienv");
    }
    if (addr === null) {
        return;
    }
    try {
        var env = envPtr !== undefined ? envPtr : Java.vm.getEnv().handle;
        var ret = new NativeFunction(addr, 'int', ['pointer'])(env);
        console.log("[QTrace] lingyi_vm_set_jnienv -> " + ret + ", env=" + env);
    } catch (e) {
        console.log("[QTrace] set jnienv failed: " + e);
    }
}

function injectTraceSo() {
    var dlopenPtr = findGlobalExport('dlopen');
    var dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);
    console.log("[QTrace] inject " + TRACE_SO_PATH);
    var handle = dlopen(Memory.allocUtf8String(TRACE_SO_PATH), 2);
    console.log("[QTrace] dlopen handle = " + handle);
    getVmCall();
    // 先传入JNIEnv，再初始化环境，最后才trace，方便分段排查
    setJniEnv();
    var init = getVmInit();
    if (init !== null) {
        console.log("[QTrace] lingyi_vm_init -> " + init());
    }
}

/* 对指定地址执行一次 trace，args 为参数值数组 */
function traceAddr(funcAddr, args, logPath) {
    var packed = prepareArgs(args);
    var logPtr = Memory.allocUtf8String(logPath);
    console.log("[QTrace] trace " + funcAddr + ", argNum=" + packed.argNum + ", log=" + logPath);
    var ret = getVmCall()(funcAddr, packed.argsPtr, packed.argNum, logPtr, 0);
    console.log("[QTrace] trace done, ret=" + ret);
    return ret;
}


/* hook 目标函数：应用调用时用 QBDI trace 一遍，并返回 trace 得到的返回值 */
function hookTarget() {
    if (targetHooked) {
        return;
    }
    var module = Process.findModuleByName(TARGET_SO);
    if (module === null) {
        console.log("[QTrace] " + TARGET_SO + " 还未加载");
        return;
    }
    var targetFuncAddr = module.base.add(TARGET_OFFSET);
    var offsetStr = targetFuncAddr.sub(module.base).toString();
    var logPath = "/data/user/0/" + APP_NAME + "/" + offsetStr + ".txt";
    var argTypes = ['pointer', 'pointer', 'pointer', 'pointer'];

    console.log("[QTrace] hook " + TARGET_SO + "+" + offsetStr + " @ " + targetFuncAddr);

    Interceptor.replace(targetFuncAddr, new NativeCallback(function (arg0, arg1, arg2, arg3) {
        // QBDI trace 期间会重新执行目标函数，先还原 hook 避免重入
        Interceptor.revert(targetFuncAddr);
        Interceptor.flush();
        targetHooked = false;

        return traceAddr(targetFuncAddr, [arg0, arg1, arg2, arg3], logPath);
    }, 'pointer', argTypes));

    targetHooked = true;
}

function onTargetLoaded() {
    injectTraceSo();
    hookTarget();
}

/* 监听 so 加载，目标 so 加载完成后再 hook */
function hookLoadLibrary() {
    ['__loader_dlopen', 'android_dlopen_ext'].forEach(function (name) {
        var addr = findGlobalExport(name);
        if (addr === null) {
            return;
        }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.soname = args[0].readCString();
                this.find = this.soname !== null && this.soname.indexOf(TARGET_SO) !== -1;
            },
            onLeave: function (retval) {
                if (this.find) {
                    onTargetLoaded();
                }
            }
        });
    });
}

setImmediate(function () {
    // 先加载 QTrace 模块，目标 so 已加载则直接 hook，否则等待 so 加载
    injectTraceSo();
    if (Process.findModuleByName(TARGET_SO) !== null) {
        hookTarget();
    } else {
        hookLoadLibrary();
    }
});

rpc.exports = {
    // frida -U -n xxx -l inject.js -e "script.exports.trace(0xe7a8, [1, 'abc'])"
    trace: function (offset, args) {
        var module = Process.getModuleByName(TARGET_SO);
        var funcAddr = module.base.add(offset);
        var logPath = "/data/user/0/" + APP_NAME + "/" + ptr(offset).toString() + ".txt";
        var ret = traceAddr(funcAddr, args, logPath);
        return { ret: ret.toString(), log: logPath };
    }
};
