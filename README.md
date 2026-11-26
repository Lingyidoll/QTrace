中文 | [English](README_en.md)

# QTrace
基于qbdi的安卓arm64真机trace工具,使用android studio构建

# Features
* arm64真机指令trace，内存读写监控
* 自定义函数监控
* 自定义jni函数监控
* 自定义libc函数监控

# Usage
0.将nativelib\src\main\cpp\qbdi-arm64\lib 目录下的libQBDI.zip解压出libQBDI.a，置于nativelib\src\main\cpp\qbdi-arm64\lib目录下。或去qbdi官方 https://github.com/QBDI/QBDI/releases/ 下载最新的libQBDI.a，注意选择andorid aarch64架构的,置于nativelib\src\main\cpp\qbdi-arm64\lib目录下

1.将trace的目标so push到/data/local/tmp目录下

2.root 环境下执行 setenforce 0

3.在 /nativelib/cpp/native_main.cpp 中，修改 initTraceEnv() 中的trace配置

   `setBufferSize` 参数是 32 位打包值：

   - `bit7~bit0`：配置状态，按 `enable_*` 调用顺序从 bit0 开始  
     `bit0` 逐指令日志(`enableDebugInsn`)、`bit1` jni trace、`bit2` obj 类名解析、`bit3` libc trace
     （method/field 名称由 JNIEnv 函数表 hook 始终记录，不受 `bit2` 影响）、
     `bit4` 安全模式：目标代码一旦要 `bl/blr/br` 进入 ART(libart/libnativehelper) 或未知模块，
     就在执行它之前停止 trace（libc/其它普通 so 照常执行，见下面"加固so崩溃"）
   - `bit31~bit8`：累计写盘阈值，等价字节数 = `参数 & 0xFFFFFF00`；为 0 表示每 trace 一条指令就写盘
   - 例如 `0x1000000A` = 256MB + jni trace + libc trace（逐指令日志和 obj 类名解析关闭）
   - 例如 `0x1000001A` = 256MB + jni trace + libc trace + 安全模式（推荐用于加固so的VM/JNI函数）
   - 注意：`bit2` 只影响 obj/clazz 类名（在 JNIEnv hook 里解析并缓存，trace 期间不调 JNI，
     不会因为 ART 抛异常崩在 `StackVisitor::WalkStack`）；method/field 名称不需要它

   ### 加固so / VM 的 JNI 函数为什么会崩

   用 `lingyi_vm_call` trace 一个 **JNI native 方法**（例如小红书的
   `com.xingin.shield.http.Native.intercept(Interceptor$Chain,J)`，`libxyass.so!0x6887C`）时，
   `trace_call` 只是"重放"：只按 AAPCS64 恢复了 x0~x7，栈是 `sp-0x4000` 挪过的，x8~x28 也不是
   调用现场的值。目标 so 里的 VM 一旦在这份上下文里调 JNI（进 libart），ART 会拿 VM 缓存里的
   `jmethodID/jobject` 去解引用，落到 linear alloc 的空洞上直接 SIGSEGV，
   frida 侧看到的就是：

   ```
   Error: access violation accessing 0x7040xxxx
       at <anonymous> (trace2.js:99:26)
   ```

   崩溃地址每次都不一样（`0x70406a4474`、`0x70406b91ec`…），但都在 ART 的 linear alloc 区，
   而且都出现在 trace 日志最后一条指令之后的那个跨模块 `BLR` 上。

   打开 `bit4` 后 QBDI 不会执行模块外的任何一条指令，日志里会留下：

   ```
   0x6fe3ccc5ac  0x4c5ac   blr  x8   ;X8=0x713b7fecb4 ...
     [STOP] call JNI CallObjectMethodV 0x713b7fecb4 [libart.so!0x...], stop before entering ART (bit4)
   ```

   此时 `lingyi_vm_call` 提前返回 0，**调用方必须接着把真实函数原生再执行一次**，
   否则被 replace 掉的原函数不会真正运行（app 会拿到 0 / 垃圾对象）。
   另外这类 VM 的缓存常常是**懒分配**的（`if (cache == 0) { cache = alloc(); memset(0); }`），
   第 1 次调用就被 QBDI 重放会把它分配成"全 0"，紧接着的原生执行就会拿 `clazz/methodID = 0`
   去调 JNI 而崩在 ART。所以模板里是**第 1 次调用交给 app 原生跑，第 2 次调用才做 trace**。
   写法见 `trace2_safe.js`（`Interceptor.revert` → `vmtrace` → `NativeFunction(原地址)`，
   未到指定次数时重新 `Interceptor.replace` 继续等下一次调用）。


4.在qbdihook.cpp中添加自定义hook，在libctrace.cpp中添加需要trace 的libc函数，在jnitrace.cpp中添加需要trace的jni函数

5.Build-Generate Apks,将自动生成libnativelib.so ,将其 push 到 /data/local/tmp目录下

6.使用第三方工具注入libnativelib.so 到目标进程，可使用项目自带的frida脚本inject.js，注入后libnativelib.so可以直接被frida调用：


```c
// libnativelib.so 对外导出的trace接口
// func_addr: 目标函数地址  args: 参数值数组  arg_num: 参数个数(最大8个)
// log_path: trace日志路径(传NULL使用默认路径)
// flags: 32位打包配置，传0沿用 initTraceEnv() 的默认配置
//        低8位开关: bit0 逐指令日志 / bit1 jni trace / bit2 obj类名解析 / bit3 libc trace
//        高24位写盘阈值: 字节数 = flags & 0xFFFFFF00
//        例: 0x1000000A = 256MB写盘 + jni trace + libc trace
size_t lingyi_vm_call(void *func_addr, size_t *args, uint32_t arg_num, const char *log_path, uint32_t flags);
```

```javascript
// frida中直接调用，不再需要shadowhook inline hook
var vmCall = new NativeFunction(addr, 'pointer',
    ['pointer', 'pointer', 'uint32', 'pointer', 'uint32']);
// 沿用默认配置
var res = vmCall(targetFunc, argsPtr, argNum, logPathPtr, 0);
// 本次trace覆盖配置: 0x1000000A
var res2 = vmCall(targetFunc, argsPtr, argNum, logPathPtr, 0x1000000A);
```

* libnativelib.so 注入后不会自动trace，所有trace都由 lingyi_vm_call 触发
* args 中的字符串/内存数据需要调用方提前分配好，参数最多8个（x0~x7）
* JNI/libc trace环境只在首次调用时初始化，后续调用复用：
  libc 地址->回调表只安装一次（`std::call_once` + 按地址查重）；
  JNI 表每次 `lingyi_vm_call` 会按 JNIEnv 函数表**重新同步**（增量、已注册就跳过），
  用于应对 JNIEnv 槽位在首次注册之后才被 patch/还原的情况，不会重复安装或丢失已有条目
* `flags` 只对本次调用生效：进入时保存调用前配置，trace 结束恢复；传 0 表示沿用当前配置
* inject.js 中已包含 prepareArgs、hook目标so、rpc调用等完整示例



# 使用教程
[QTrace：基于QBDI的高稳定，高定制的trace工具](https://bbs.kanxue.com/thread-290574.htm)

# trace日志格式

```
0x743584a838	0x7838		ldr	x1, [x1, #1384]	;X1=0x7482a19bd8 -> 0x7482652404
0x743584a83c	0x783c		ldr	x8, [sp, #16]	;X8=0x744b07d200 -> 0x744b07ed18, SP=0x744b07d130
0x743584a850	0x7850		blr	x8	;X8=0x7740f4d040, SP=0x744b07d130, LR=0x743585b884 -> 0x743584a854
Call addr: malloc(0x80)
       return x0 = 0x744b07ed10

0x7435845bec	0x2bec		br	x17	;X17=0x7740f41540
Call addr: strcmp("java/lang/Class", "java/lang/String")
       return x0 = 0x13

0x743584xxxx	0xxxx		blr	x8	;X8=0x7740f4xxxx
Call addr: memcpy(dst=0x78c0062540, src=0x78c0061970[04 00 00 00 04 00 00 00 00 00 00 00 50 00 00 00], len=0x51)
       return x0 = 0x78c0062540

0x7435845d10	0x2d10		svc	#0	;X8=0xde
  [SYSCALL] nr=222(0xde) x0=0x0 x1=0x1000 x2=0x3 x3=0x22 x4=0xffffffff x5=0x0

0x743584a8f0	0x78f0		blr	x8	;X8=0x7740f31678, SP=0x744b07d130, LR=0x743585b884 -> 0x743584a8f4
Call addr: 0x7740f31678 [libc.so!0x6d678]

0x7435858910	0x15910		blr	x8	;X8=0x748284d50c, SP=0x744b078bc0, LR=0x743587c290 -> 0x7435858914
  [JNI] CallObjectMethodV(env=0x7380016ac0, obj=0x74001234, methodID=0x6f914da8, args=[])
      jobject CallObjectMethodV(JNIEnv *env, jobject obj, jmethodID methodID, va_list args);
      obj = java.lang.String
      method = toString
      return x0 = 0x74005678 (java.lang.String)
```

* 第1列：指令绝对地址；第2列：模块内偏移；第3列：反汇编
* `;` 之后：写寄存器为 `before -> after`（值未变化时只输出一次），读寄存器输出当前值
* `bl/blr` 会额外输出 `SP`（调用时栈指针）和 `LR`（`before -> after`，after即返回地址）
* **已 hook 的函数**输出 `Call addr: 函数名(参数)`，下一行输出 `return x0 = 0x...`，
  不再带原始地址，也不再输出 `Entering system lib` / `Return to`
* libc 缓冲区参数**一律输出十六进制**：`0x地址[hex bytes]`；如果内容是可打印字符串，
  会在末尾再附上 `"字符串"` 方便阅读（例如 `src=0x...[68 65 6c 6c 6f] "hello"`）
* **未 hook 的跨模块调用**输出 `Call addr: 0x地址 [模块名!偏移]`（能解析到符号时显示符号名），
  目标 so 内部的 `bl`/`blr`（含 PLT 前的本地跳转）只保留指令行
* JNI 函数统一输出 `[JNI] 函数名(参数)`，下一行输出该函数的 C 原型，再输出 `obj/clazz` 解析出的
  java 类名（如 `obj = java.lang.String`）、`method = 方法名` / `field = 字段名` 和
  `return x0 = ...`；变参（`V` / 非`V` / `A` 三种形态）一律按 `GetMethodID` 记下的**方法签名**逐个解码，
  参数个数和类型都以签名为准（如 `args=[java.lang.String@0x74001234, jint 0]`），无参方法就是 `args=[]`；
  签名没记到时输出 `args=<sig unknown, va=0x...>`，不会再把寄存器保存区里的脏槽位当成参数打出来
* `obj/clazz` 的类名受 `bit2` 控制，但**trace 期间不调用任何 JNI**，全部靠同一套 JNIEnv 函数表 hook 记账：
  `FindClass` 记录 `jclass -> 类名`（名字直接来自入参，无反射）、`GetObjectClass` 记录 `obj -> jclass`、
  `Get*ID` 在类名缺失时用 `Class.getName()` 兜底补一次；trace 回调只查表。
  因此应用调用过 `FindClass/GetObjectClass` 的类/对象都能显示类名；这样也避免了在 QBDI 改写的栈上
  让 ART 抛异常（会崩在 `StackVisitor::WalkStack`）
* 引用句柄会变：`NewGlobalRef/NewLocalRef` 返回的是**新句柄**（值不等于源引用）。这两个函数**不 hook**
  （在函数表上拦引用函数会导致崩溃），而是在已有的 QBDI 回调 `trace_ReferenceFunc` 里把源句柄上的
  类信息（`jclass -> 类名` 或 `obj -> jclass`）继承给新句柄，所以全局引用也能显示类名；
  `DeleteGlobalRef/DeleteWeakGlobalRef` 后句柄值会被 ART 回收复用，同一个回调里把该句柄的类信息删掉，
  避免复用后打印成上一个类（都是纯查表操作，trace 期间不调 JNI）
* 局部引用还会在 native 帧返回时被 ART 自动回收（我们收不到 `DeleteLocalRef`），句柄值照样会被复用。
  所以对**创建出来就已知类型**的引用（`NewStringUTF`/`NewString` 一定是 `java.lang.String`、
  `NewObject*`/`AllocObject` 一定是入参 `clazz` 的实例、`FindClass` 的 `jclass`）直接按句柄记下类名，
  并清掉该句柄上的旧映射；trace 时这类记录优先于 `obj -> jclass` 反查，
  不会再出现"刚创建的 String 显示成上一个对象（如 `com.meituan.robust.PatchProxy`）"的情况
* JNI 回调是在**被调用函数返回之后**才执行的（为了拿到 `return x0`），此时 ART 已经把 `va_list`
  消费完（`gr_offs`/`vr_offs` 被推进到末尾）。所以变参解码不能用 `va_list` 结构体里的现成偏移，
  而是按 AAPCS64 的 `va_start` 规则重建初值：`gr_offs = -(8 - 命名通用参数个数) * 8`、
  `vr_offs = -8 * 16`（命名参数个数：`Call*Method`/`CallStatic*Method`/`NewObject*` 为 3，
  `CallNonvirtual*Method` 为 4），浮点参数每槽 16 字节，再按方法签名逐个取值
* `method`/`field` 名称来自 `GetMethodID/GetStaticMethodID/GetFieldID/GetStaticFieldID`：
  在 `lingyi_vm_set_jnienv`（`setup_jni_env`）/ `initJni` 拿到 JNIEnv 的那一刻，就直接在这几个
  JNIEnv 函数表入口上装 hook，把 `id -> 名称` 写进缓存表并一直记录（与 `bit2` 无关，
  trace 开始前拿到的 id 也能查到），trace 时只查表，不做任何反射反查
* 解析失败时输出 `obj/clazz = <unknown>`（或 `<null>`）、`method/field = <unknown>`，不影响后续trace
* 解析 `obj/method` 使用的是被 trace 代码**本次 JNI 调用自己的 `JNIEnv*`（x0）**，
  不会混用初始化时保存的其它线程 env（JNI 局部引用与线程/env 绑定，混用会导致 ART 崩溃）
* `Call*Method` / `CallStatic*Method` / `CallNonvirtual*Method` 全系列（Object/Boolean/Byte/Char/
  Short/Int/Long/Float/Double/Void，含 `V` 和 `A` 版本），以及字段读写、数组、引用、字符串、异常、
  监视器等常用 JNI 函数都已注册（见 `native_main.cpp`）
* libc 侧已注册：内存/字符串/文件/线程/时钟/property、`mmap`/`munmap`/`dlsym`/`strdup` 等常用函数
  （见 `libctrace.cpp`），bionic 内部实现（`__strlen_aarch64`、`__memset_aarch64`）在 `dlsym`
  失败时会回退到 ELF 动态符号表解析
* 系统调用：AArch64 的 `svc` 指令会在指令行下面输出 `[SYSCALL] nr=系统调用号(0x..) x0~x5=参数`

