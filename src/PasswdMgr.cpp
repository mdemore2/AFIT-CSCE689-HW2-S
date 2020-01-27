#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include <ext/stdio_filebuf.h>
#include <fstream>
#include <string>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"

const int hashlen = 32;
const int saltlen = 16;

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {

}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::vector<uint8_t> passwd, salt;

   bool result = findUser(name, passwd, salt);

   return result;
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> passhash; // hash derived from the parameter passwd
   std::vector<uint8_t> salt;

   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, salt))
      return false;

   hashArgon2(passhash, salt, passwd, &salt);

   if (userhash == passhash)
      return true;

   return false;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {

   FileFD pwfile(_pwd_file.c_str());

   // You may need to change this code for your specific implementation

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      std::string uname;
      std::string readNewLine;

      std::vector<uint8_t> hash, salt; //do these need to be pointers?
      
      try{

         if(pwfile.readStr(uname) < 0) eof = true;
   
         if(uname.compare(name) == 0)
         {
            //write password
            genSalt(&salt,saltlen);
            hashArgon2(hash,salt,passwd,&salt);

            pwfile.writeBytes(hash);
            pwfile.writeBytes(salt);
            pwfile.writeByte('\n');
            //close and return
            pwfile.closeFD();
            return true;
         }
         else
         {
            if(pwfile.readStr(readNewLine) < 0) return false; //read last newline from hash/salt line
         }

      }catch(pwfile_error){}

   }

   pwfile.closeFD();
   return false;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   std::string readNewLine;
   try{

      if(pwfile.readStr(name) < 0) return false;
   
      if(pwfile.readBytes(hash,32) < 0) return false;
  
      if(pwfile.readBytes(salt,16) < 0) return false;
   
      if(pwfile.readStr(readNewLine) < 0) return false; //read last newline from hash/salt line

   }catch(pwfile_error){}


   return true;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   int results = 0;

   try{
   std::vector<char> name_vector(name.begin(),name.end());

   results += pwfile.writeBytes(name_vector);
   results += pwfile.writeByte('\n');

   results += pwfile.writeBytes(hash);
   results += pwfile.writeBytes(salt);
   results += pwfile.writeByte('\n');
   } catch(pwfile_error){}
  



   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {

   FileFD pwfile(_pwd_file.c_str());

   // You may need to change this code for your specific implementation

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      std::string uname;

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, const char *in_passwd, std::vector<uint8_t> *in_salt) {
  
   if(in_salt->size() < saltlen) throw std::runtime_error("invalid salt length");

   uint8_t salt[saltlen];

   for(unsigned int i=0;i<saltlen;i++)
   {
      salt[i] = *(in_salt)[i]
   }

   uint8_t hash[hashlen];

   argon2i_hash_raw(2,(1<<16),1,in_passwd,strlen(in_passwd),salt,saltlen,hash,hashlen);
   
   ret_hash.clear();
   ret_hash.reserve(hashlen);

   for(unsigned int i=0; i<hashlen;i++)
   {
      ret_hash.push_back(hash[i]);
   }
   

}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   
   std::vector<uint8_t> hash, salt; //do these need to be pointers?
   std::string namePass(name);
   
   
   if(checkUser(name))
   {
      return;
   }
   else
   {
      //hash and pass
      genSalt(&salt,saltlen);
      hashArgon2(hash,salt,passwd,&salt);

      FileFD pwfile(_pwd_file.c_str());
      if (!pwfile.openFile(FileFD::readfd)) throw pwfile_error("Could not open passwd file for reading");

      if(writeUser(pwfile,namePass,hash,salt) < 0) throw pwfile_error("Could not write user to file");
   }
   
}

void PasswdMgr::genSalt(std::vector<uint8_t> *s, const int len) {
    
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s->push_back( alphanum[rand() % (sizeof(alphanum) - 1)] );
    }

}
