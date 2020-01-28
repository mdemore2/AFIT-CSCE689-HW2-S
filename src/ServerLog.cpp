#include <list>
#include <memory>
#include "Server.h"
#include "FileDesc.h"
#include "ServerLog.h"

ServerLog::ServerLog(){
    //_logfile =  FileFD("server.log");
    _logfile.openFile(FileFD::appendfd);

}

ServerLog::ServerLog(std::string logfileName){
    _logfile =  FileFD(logfileName.c_str());
    _logfile.openFile(FileFD::appendfd);
}

ServerLog::~ServerLog() {
    _logfile.closeFD();
}

void ServerLog::writeLog(std::string msg)
{
    addTimeStamp();
    if(msg.back() != '\n')
    {
        msg.push_back('\n');
    }
    _logfile.writeFD(msg);
}

void ServerLog::strerrLog(std::string msg)
{
    _logfile.writeFD("ERROR: ");
    writeLog(msg);
}

void ServerLog::addTimeStamp()
{
    time_t rawtime;
    struct tm * timeinfo;

    time (&rawtime);
    timeinfo = localtime (&rawtime);

    _logfile.writeFD(asctime(timeinfo));
    _logfile.writeByte(' ');

}