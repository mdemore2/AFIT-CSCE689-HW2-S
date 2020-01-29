#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include "TCPConn.h"
#include "strfuncts.h"
#include "PasswdMgr.h"
#include "ServerLog.h"

// The filename/path of the password file
const char pwdfilename[] = "passwd";

PasswdMgr passmgr = PasswdMgr(pwdfilename);

TCPConn::TCPConn(){ 

}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   return _connfd.acceptFD(server);
}

/**********************************************************************************************
 * sendText - simply calls the sendText FileDesc method to send a string to this FD
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

int TCPConn::sendText(const char *msg) {
   return sendText(msg, strlen(msg));
}

int TCPConn::sendText(const char *msg, int size) {
   if (_connfd.writeFD(msg, size) < 0) {
      return -1;  
   }
   return 0;
}

/**********************************************************************************************
 * startAuthentication - Sets the status to request username
 *
 *    Throws: runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPConn::startAuthentication() {

   _status = s_username;

   _connfd.writeFD("Username: ");

}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;

   try {
      switch (_status) {
         case s_username:
            getUsername();
            break;

         case s_passwd:
            getPasswd();
            break;
   
         case s_changepwd:
         case s_confirmpwd:
            changePassword();
            break;

         case s_menu:
            getMenuChoice();

            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.";
      disconnect();
      return;
   }

   nanosleep(&sleeptime, NULL);
}

/**********************************************************************************************
 * getUsername - called from handleConnection when status is s_username--if it finds user data,
 *               it expects a username and compares it against the password database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getUsername() {
   
   //get next line from socket
   if(!getUserInput(_username))
   {
      sendText("error reading user input");
   }
   clrNewlines(_username);

   //find user
   if(passmgr.checkUser(_username.c_str()))
   {
      _status = s_passwd;
    
   }
   else
   {
      std::string ipaddr;
      getIPAddrStr(ipaddr);

      //log attempt
      std::string msg = "Unrecognized user. User: " + _username;
      msg += " IP: " + ipaddr;
      _server_log.writeLog(msg);

      //disconnect user
      sendText("Unrecognized user.");
      disconnect();
   }
}

/**********************************************************************************************
 * getPasswd - called from handleConnection when status is s_passwd--if it finds user data,
 *             it assumes it's a password and hashes it, comparing to the database hash. Users
 *             get two tries before they are disconnected
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getPasswd() {
   
   sendText("Password: ");
   std::string password;

   getUserInput(password);
   clrNewlines(password);
   

   std::string ipaddr;
   getIPAddrStr(ipaddr);

   std::string msg;

   if(passmgr.checkPasswd(_username.c_str(),password.c_str()))
   {
      //if match, login and send menu
      _status = s_menu;
      //log user + ip
      msg = "Succssful Login. User: " + _username;
      msg += " IP: " + ipaddr;
      _server_log.writeLog(msg);

      sendMenu();
      return;
   

   }
   else
   {
      //increment attempt counter
      _pwd_attempts++;
      sendText("Incorrect Password. Try Again.\n");
   }

   //if two incorrect entries, disconnect
   if(_pwd_attempts > 1)
   {
      //log username and ip
      msg = "Incorrect Password. User: " + _username;
      msg += " IP: " + ipaddr;
      _server_log.writeLog(msg);
      
      sendText("Too many attempts. Disconnecting.\n");
      //disconnect
      disconnect();

   }
   else
   {
      //give extra chance to enter correct password
      getPasswd();
   }
   
}

/**********************************************************************************************
 * changePassword - called from handleConnection when status is s_changepwd or s_confirmpwd--
 *                  if it finds user data, with status s_changepwd, it saves the user-entered
 *                  password. If s_confirmpwd, it checks to ensure the saved password from
 *                  the s_changepwd phase is equal, then saves the new pwd to the database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::changePassword() {

   if(_status == s_changepwd)
   {
      getUserInput(_newpwd);
      clrNewlines(_newpwd);
      _status = s_confirmpwd;
      //store new password, call again to verify
      changePassword();
   }
   else
   {
      //verify new password
      sendText("Re-enter new password: ");
      std::string checkPwd;
      
      getUserInput(checkPwd);
      clrNewlines(checkPwd);

      if(checkPwd == _newpwd)
      {
         passmgr.changePasswd(_username.c_str(),_newpwd.c_str());
         _newpwd.clear();
         sendText("Password changed.");
         sendMenu();
         //update password if correct
      }
      else
      {
         sendText("Passwords do not match.");
         sendMenu();
         //spit back out to menu if incorrect
      }
      _status = s_menu;

      
   }
   


}


/**********************************************************************************************
 * getUserInput - Gets user data and includes a buffer to look for a carriage return before it is
 *                considered a complete user input. Performs some post-processing on it, removing
 *                the newlines
 *
 *    Params: cmd - the buffer to store commands - contents left alone if no command found
 *
 *    Returns: true if a carriage return was found and cmd was populated, false otherwise.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getUserInput(std::string &cmd) {
   std::string readbuf;

   // read the data on the socket
   _connfd.readFD(readbuf);

   // concat the data onto anything we've read before
   _inputbuf += readbuf;

   // If it doesn't have a carriage return, then it's not a command
   int crpos;
   if ((crpos = _inputbuf.find("\n")) == std::string::npos)
      return false;

   cmd = _inputbuf.substr(0, crpos);
   _inputbuf.erase(0, crpos+1);

   // Remove \r if it is there
   clrNewlines(cmd);

   return true;
}

/**********************************************************************************************
 * getMenuChoice - Gets the user's command and interprets it, calling the appropriate function
 *                 if required.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getMenuChoice() {
   if (!_connfd.hasData())
      return;
   std::string cmd;
   if (!getUserInput(cmd))
      return;
   lower(cmd);      

   std::string msg;
   if (cmd.compare("hello") == 0) {
      _connfd.writeFD("Annyong.\n");
   } else if (cmd.compare("menu") == 0) {
      sendMenu();
   } else if (cmd.compare("exit") == 0) {
      _connfd.writeFD("Disconnecting.\n");
      disconnect();
   } else if (cmd.compare("passwd") == 0) {
      _connfd.writeFD("New Password: ");
      _status = s_changepwd;
   } else if (cmd.compare("1") == 0) {
      msg += "It is 2014 and I have no idea what is going on in my life!\n";
      _connfd.writeFD(msg);
   } else if (cmd.compare("2") == 0) {
      _connfd.writeFD("They say that the world is one, but if the world is one how come you never come around anymore?\n");
   } else if (cmd.compare("3") == 0) {
      _connfd.writeFD("My boy, we don't see each other much.\n");
   } else if (cmd.compare("4") == 0) {
      _connfd.writeFD("And when I fall asleep, which part of me writes the dream?\n");
   } else if (cmd.compare("5") == 0) {
      _connfd.writeFD("It's not going to happen.\n");
   } else {
      msg = "Unrecognized command: ";
      msg += cmd;
      msg += "\n";
      _connfd.writeFD(msg);
   }

}

/**********************************************************************************************
 * sendMenu - sends the menu to the user via their socket
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::sendMenu() {
   std::string menustr;

   menustr += "Available choices: \n";
   menustr += "  1). Hey, Space Cadet\n";
   menustr += "  2). Unforgiving Girl (She's Not A)\n";
   menustr += "  3). My Boy\n";
   menustr += "  4). Maud Gone\n";
   menustr += "  5). Don't Remind Me\n\n";
   menustr += "Other commands: \n";
   menustr += "  Hello - self-explanatory\n";
   menustr += "  Passwd - change your password\n";
   menustr += "  Menu - display this menu\n";
   menustr += "  Exit - disconnect.\n\n";

   _connfd.writeFD(menustr);
}


/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {

   //log username and ip
   std::string ipaddr;
   getIPAddrStr(ipaddr);

   std::string msg = "Disconnect. User: " + _username;
   msg += " IP: " + ipaddr;

   _server_log.writeLog(msg);

   _connfd.closeFD();
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connfd.isOpen();
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
void TCPConn::getIPAddrStr(std::string &buf) {
   return _connfd.getIPAddrStr(buf);
}

