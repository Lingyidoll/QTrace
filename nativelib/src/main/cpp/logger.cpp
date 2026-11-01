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

    _logger = new logger();
    _logger->buf = sdsempty();
    _logger->logfile = logfile;
    _logger->lastwrite = 0;
    _logger->totallen = 0;
    _logger->fd = open(_logger->logfile.c_str(),O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (_logger->fd < 0)
    {
        LOGE("open trace log %s fail:%s", _logger->logfile.c_str(), strerror(errno));
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
    if(_logger != nullptr)
    {
        sdsfree(_logger->buf);
        close(_logger->fd);
    }
    delete _logger;
    _logger = nullptr;
}

void appendlog(const char* str)
{
      if(_logger != nullptr)
      {
          _logger->buf = sdscat(_logger->buf, str);
      }
}

void appendlog_n(const char* str, size_t len) {
    if (_logger != nullptr)
        _logger->buf = sdscatlen(_logger->buf, str, len);
}

void appendlogendl()
{
    appendlog("\n");
}

void appendformat(const char* format,...)
{
    va_list ap;
    va_start(ap, format);
    _logger->buf = sdscatvprintf(_logger->buf,format,ap);
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
    if(_logger == nullptr)
    {
        return;
    }
    if(_logger->fd < 0)
    {
        //日志文件打开失败，直接丢弃缓存，避免缓存一直增长
        sdsfree(_logger->buf);
        _logger->buf = sdsempty();
        return;
    }
    _logger->totallen = _logger->lastwrite + sdslen(_logger->buf);
    LOGE("write log:%lx,%lx,%s", _logger->lastwrite,_logger->totallen,_logger->logfile.c_str());
    /*
    std::ofstream out(_logger->logfile.c_str(), std::ios::app);
    if (!out.is_open()) {
        LOGE("Failed to create trace log file: %s", _logger->logfile.c_str());
        return ;
    }
    out.write(_logger->buf, sdslen(_logger->buf));
    out.close();
    */
    write_all(_logger->fd,_logger->buf, sdslen(_logger->buf));
    _logger->lastwrite = _logger->totallen;
    sdsfree(_logger->buf);
    _logger->buf = sdsempty();
    _logger->buf = sdsMakeRoomFor(_logger->buf, 2*bufsize);
    LOGE("write log done!");
}