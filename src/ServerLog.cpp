#include <list>
#include <memory>
#include "Server.h"
#include "FileDesc.h"
#include "ServerLog.h"

ServerLog::ServerLog(){
    _logfile.openFile(FileFD::appendfd);
    //open file for logging
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
    //add error prefix
    writeLog(msg);
}

void ServerLog::addTimeStamp()
{
    //write timestamp before message to be logged
    time_t rawtime;
    struct tm * timeinfo;

    time (&rawtime);
    timeinfo = localtime (&rawtime);

    _logfile.writeFD(asctime(timeinfo));
    _logfile.writeByte(' ');

}