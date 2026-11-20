//
// Created by zgy on 2025/12/3.
//
#include "logger.h"
#include "TraceLogger.h"
#include "sds.h"
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include "unistd.h"
#include "vm.h"
logger *_logger = nullptr;

/* 当前线程正在使用的 logger（支持嵌套/多线程并发 trace） */
static thread_local logger *t_logger = nullptr;

logger* currentLogger()
{
    return t_logger;
}

logger* swapLogger(logger* lg)
{
    logger* prev = t_logger;
    t_logger = lg;
    return prev;
}

static void initLoggerInternal(const char *log_path, size_t function_address)
{
    std::string logfile;
    if (log_path != nullptr && log_path[0] != '\0')
    {
        logfile = log_path;
        //保证日志文件所在目录存在，例如 /data/user/0/<pkg>/trace_logs/
        size_t pos = logfile.find_last_of('/');
        if (pos != std::string::npos && pos > 0)
        {
            ensureLogDirectory(logfile.substr(0, pos + 1));
        }
        LOGI("use custom log path:%s", logfile.c_str());
    }
    else
    {
        logfile = getLogPath(LogType::QBDI_TRACE, (void *) function_address);
    }

    t_logger = new logger();
    t_logger->buf = sdsempty();
    t_logger->logfile = logfile;
    t_logger->lastwrite = 0;
    t_logger->totallen = 0;
    t_logger->fd = open(t_logger->logfile.c_str(),O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (t_logger->fd < 0)
    {
        LOGE("open trace log %s fail:%s", t_logger->logfile.c_str(), strerror(errno));
    }
}

void initLogger(size_t function_address)
{
    initLoggerInternal(nullptr, function_address);
}

void initLoggerWithPath(const char* log_path, size_t function_address)
{
    initLoggerInternal(log_path, function_address);
}

void deleteLogger()
{
    if(t_logger != nullptr)
    {
        sdsfree(t_logger->buf);
        close(t_logger->fd);
        delete t_logger;
        t_logger = nullptr;
    }
}

void appendlog(const char* str)
{
      if(t_logger != nullptr)
      {
          t_logger->buf = sdscat(t_logger->buf, str);
      }
}

void appendlog_n(const char* str, size_t len) {
    if (t_logger != nullptr)
        t_logger->buf = sdscatlen(t_logger->buf, str, len);
}

void appendlogendl()
{
    appendlog("\n");
}

void appendformat(const char* format,...)
{
    //没有logger时直接丢弃，避免trace收尾/回调时序异常时空指针崩溃
    if(t_logger == nullptr)
    {
        return;
    }
    va_list ap;
    va_start(ap, format);
    t_logger->buf = sdscatvprintf(t_logger->buf,format,ap);
    va_end(ap);
}

static bool write_all(int fd, const char* buf, size_t count) {
    size_t written = 0;
    while (written < count) {
        ssize_t n = write(fd, buf + written, count - written);
        if (n < 0) {
            if (errno == EINTR) continue;   // 被信号打断,重试
            LOGE("write failed: %s", strerror(errno));
            return false;
        }
        written += n;
    }
    return true;
}

void writelog()
{
    if(t_logger == nullptr)
    {
        return;
    }
    if(t_logger->fd < 0)
    {
        //日志文件打开失败，直接丢弃缓存，避免缓存一直增长
        sdsfree(t_logger->buf);
        t_logger->buf = sdsempty();
        return;
    }
    t_logger->totallen = t_logger->lastwrite + sdslen(t_logger->buf);
    LOGE("write log:%lx,%lx,%s", t_logger->lastwrite,t_logger->totallen,t_logger->logfile.c_str());
    /*
    std::ofstream out(_logger->logfile.c_str(), std::ios::app);
    if (!out.is_open()) {
        LOGE("Failed to create trace log file: %s", _logger->logfile.c_str());
        return ;
    }
    out.write(_logger->buf, sdslen(_logger->buf));
    out.close();
    */
    write_all(t_logger->fd,t_logger->buf, sdslen(t_logger->buf));
    t_logger->lastwrite = t_logger->totallen;
    sdsfree(t_logger->buf);
    t_logger->buf = sdsempty();
    t_logger->buf = sdsMakeRoomFor(t_logger->buf, 2*bufsize);
    LOGE("write log done!");
}