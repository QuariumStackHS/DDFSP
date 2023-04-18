#include <chrono>
#include <cstdio>
#include <string>
#include <cstring>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <sys/stat.h>
#include "../SHA256/sha256.h"
#include "../b64/b64.hpp"
inline bool exists (const std::string& name) {
  struct stat buffer;   
  return (stat (name.c_str(), &buffer) == 0); 
}
#define SERVER_CERT_FILE "./cert.pem"
#define SERVER_PRIVATE_KEY_FILE "./key.pem"
namespace fs = ::std::filesystem;

using namespace std;
int chunksize = (1024 / 0.75) - 1;
class DDindex{
    public:
    string Directory="Storage/Index/";
    DDindex(string directory){
        Directory=directory;
    }
    bool index_append(string filename,string hashs){
        ofstream F(Directory+filename,ios::app);
        F<<hashs;
        F.close();
        return 0;
    }
    string index_get(string filename){
        ifstream F(Directory+filename);
        stringstream ss;
        ss<<F.rdbuf();
        string s=ss.str();
        return s;
    }
};
class Datadedup
{
public:
    string Directory="Storage/Blocks/";
    Datadedup(string directory)
    {
        Directory = directory;
    }
    string write_packet(string pack, string hash)
    {
        //if (strcmp(sha256(b64decode(pack)).c_str(), hash.c_str()) == 0)
        //{
            ofstream Block(this->Directory + hash);
            Block << b64decode(pack);
            Block.close();
            //cout<<hash<<endl;
            //sleep(5);
        //}
        //else cout<<"invalid  "<<sha256(b64decode(pack)).c_str()<<"    "<< hash.c_str()<<endl;
        /*if (strcmp(SHA1::from_file(Directory + hash).c_str(), hash.c_str()) != 0)
        {
            ofstream gBlock(Directory + SHA1::from_file(Directory + hash));
            gBlock << b64decode(pack);
            gBlock.close();
        }*/
        return sha256(b64decode(pack));
    }
    string read_packet(string hash)
    {
        ifstream Block(Directory + hash);
        stringstream ss;
        ss << Block.rdbuf();
        if (strcmp(hash.c_str(), sha256(ss.str()).c_str()) == 0)
        {

            return b64encode(ss.str());
        }
        else
        {
            return "!";
        }
    }
};