//
// Created by fang on 23-12-19.
//

#ifndef QBDIRECORDER_LOGGER_H
#define QBDIRECORDER_LOGGER_H
#include <android/log.h>
#include "sstream"
#include "fstream"
#include "sds.h"
using namespace std;
// 日志
#define LOG_TAG "QTrace"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

struct logger{
    sds buf;
    std::string logfile;
    int64_t lastwrite;
    int64_t totallen;
    int fd;
};

extern logger *_logger;

/*
 * 支持"同时/嵌套 trace 多个函数"：
 * logger 不再用全局单例，而是每个线程各持一份（thread_local），
 * trace_call 进出时用 swapLogger() 保存/恢复，所以嵌套 trace 不会写乱外层的日志。
 */
logger* currentLogger();
/* 替换当前线程的 logger，返回原来的那个（用于保存/恢复） */
logger* swapLogger(logger* lg);

void initLogger(size_t function_address);
/* 使用调用方指定的日志路径初始化logger，log_path为空时退化为默认路径 */
void initLoggerWithPath(const char* log_path, size_t function_address);
void deleteLogger();
void writelog();
void appendlog(const char* str);
void appendlog_n(const char* str, size_t len);
void appendlogendl();
void appendformat(const char* format,...);

#endif //QBDIRECORDER_LOGGER_H
