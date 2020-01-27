#ifndef SERVERLOG_H
#define SERVERLOG_H

#include <list>
#include <memory>
#include "Server.h"
#include "FileDesc.h"
#include "TCPConn.h"

class ServerLog
{
public:
    ServerLog();
    ServerLog(std::string logfileName);
    ~ServerLog();

    void writeLog(std::string msg);
    void strerrLog(std::string msg);
    void addTimeStamp();



private:

    FileFD _logfile = FileFD("server.log");

};


#endif
