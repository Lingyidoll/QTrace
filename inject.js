function prepareArgs(args) {
    console.log(args[0])
    if (args === undefined || !Array.isArray(args)) {
        args = [];
    }
    var argNum = args.length;
    var argSize = Process.pointerSize * argNum;
    var argsPtr = Memory.alloc(argSize);

    for (var i = 0; i < argNum; i++) {
        var arg = args[i];
        console.log("arg",i,arg)
        var argPtr;
        if (!arg) {
            arg = 0
        }
        if (arg instanceof NativePointer) {
            // 如果是 NativePointer，直接使用
            argPtr = arg;
        } else if (typeof arg === 'number') {
            // 如果是数字，直接转换为指针
            argPtr = ptr(arg);
        } else if (typeof arg === 'string') {
            // 如果是字符串，分配内存并获取指针
            argPtr = Memory.allocUtf8String(arg);
        } else if (typeof arg === 'object' && arg.hasOwnProperty('handle')) {
            // 如果是带有 handle 属性的对象（如 JNIEnv）
            argPtr = arg.handle;
        } else if (typeof arg === 'object' && arg instanceof ArrayBuffer) {
            // 如果是二进制数据，分配内存并写入数据
            var dataPtr = Memory.alloc(arg.byteLength);
            Memory.writeByteArray(dataPtr, arg);
            argPtr = dataPtr;
        } else {
            console.error('Unsupported argument type at index ' + i + ':', typeof arg);
            throw new TypeError('Unsupported argument type at index ' + i + ': ' + typeof arg);
        }
        // 将参数指针写入参数数组
        ptr(argsPtr.add(i * Process.pointerSize)).writePointer(argPtr)
    }

    return {
        argsPtr: argsPtr,
        argNum: argNum
    };
}

var vmtraceAddr;
var vmtrace;
var envInit;
var targetSo = "libGameVMP.so"
var appName = "com.shizhuang.duapp"


function hook_sub_jniOnload() {
    var aimbase = Process.getModuleByName(targetSo).base;
    console.log("start hook");
    var targetFuncAddr = aimbase.add(0xe7a8);
    Interceptor.replace(targetFuncAddr, new NativeCallback(function (arg0,arg1,arg2,agr3) {
        console.log("trace调用了");
        Interceptor.revert(targetFuncAddr);
        Interceptor.flush();
        var args = [arg0,arg1,arg2,agr3];
        var {argsPtr, argNum} = prepareArgs(args);
        console.log(`argsPtr:${argsPtr},argNum:${argNum}`)
        var argPtr1 = Memory.allocUtf8String("/data/user/0/" + appName + "/0xe7a8.txt");
        // flags: 0 = 沿用 initTraceEnv() 默认配置
        // 也可传打包值按本次trace覆盖，例如 0x1000000A = 256MB + jni trace + libc trace
        var res = vmtrace(targetFuncAddr, argsPtr, argNum, argPtr1, 0);
        console.log(res)
        return res;
    }, 'pointer', ['pointer','pointer','pointer','pointer']));
}

function hook_soload() {
    var dlopen = new NativeFunction(Module.getGlobalExportByName('dlopen'), 'pointer', ['pointer', 'int']);
    var handle = dlopen(Memory.allocUtf8String("/data/local/tmp/libnativelib.so"), 2);
    console.log("dlopen handle =", handle);
    var mod = Process.getModuleByName("libnativelib.so");
    var setEnv = new NativeFunction(mod.getExportByName("lingyi_vm_set_jnienv"), 'int', ['pointer']);
    console.log("set_jnienv ret =", setEnv(Java.vm.getEnv().handle));
    var init = new NativeFunction(mod.getExportByName("lingyi_vm_init"), 'int', []);
    console.log("init ret =", init());
    vmtrace = new NativeFunction(mod.getExportByName("lingyi_vm_call"), 'pointer',
        ['pointer', 'pointer', 'uint32', 'pointer', 'uint32']);
}

function IL() {
    Java.perform(function () {
        var NCall = Java.use("lte.NCall");
        var IntegerCls = Java.use("java.lang.Integer");
        var StringCls = Java.use("java.lang.String");
        var type = IntegerCls.$new(564);
        var data = StringCls.$new("knGGXR0bR7LQn4eRCvJsdUI/ZDJvCi67kP1b6XLrr7B8Bv5OyV2sUNh/iwPVC9eTEaHqyIRnCc3ruo9uVyYbKnKBlb/j3PXG4tBjclOeWvKU6kzFap0hcSNIj4zWhbSVJIF/J+1BF0TpDclJu8JpfTST0WBSsK9iGIzL5TZjz5aq0s2YHzgAe18A/taUJTyGeOqucaMIWSYF3SsiznMfS07HW+dbZ9KWxcs/dhy8a5y4Oc9YeSFctar78MgtafRYJ7hVZHD2VjUNUn/3faBMiQJQS06bbe/JkutuvuzwocwAoMUfZeP0qtv/SM2w+A2c");
        var newArr = Java.array('java.lang.Object', [type, data]);
        console.log("JNI_GetCreatedJavaVMs:" +Module.getGlobalExportByName("JNI_GetCreatedJavaVMs"))
        hook_soload()
        hook_sub_jniOnload();
        var result = NCall.IL.overload('[Ljava.lang.Object;').call(NCall, newArr);
        console.log("IL result = " + result);
    });
}



