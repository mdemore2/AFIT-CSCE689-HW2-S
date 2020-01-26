#ifndef PASSWDMGR_H
#define PASSWDMGR_H

#include <string>
#include <stdexcept>
#include "FileDesc.h"

/****************************************************************************************
 * PasswdMgr - Manages user authentication through a file
 *
 ****************************************************************************************/

class PasswdMgr {
   public:
      PasswdMgr(const char *pwd_file);
      ~PasswdMgr();

      bool checkUser(const char *name);
      bool checkPasswd(const char *name, const char *passwd);
      bool changePasswd(const char *name, const char *newpassd);
   
      void addUser(const char *name, const char *passwd);

      void hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, const char *passwd, std::vector<uint8_t> *in_salt = NULL);

   private:
      bool findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt);
      bool readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt);
      int writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt);

      void genSalt(std::vector<uint8_t> *s, const int len);

      std::string _pwd_file;
};

#endif
