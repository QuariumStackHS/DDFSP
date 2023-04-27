//
//  client.cc
//
//  Copyright (c) 2019 Yuji Hirose. All rights reserved.
//  MIT License
//

#include "../common/httplib/httplib.hpp"
#include <thread>
// #include "../common/b64/b64.hpp"
// #include "../common/SHA256/sha256.h"
#include <iostream>
#include <sys/stat.h>
#include <sstream>
#include <time.h>
#include <ctime>
#include "../common/httplib/Dedupmf.hpp"
#define RESET "\033[0m"
#define BLACK "\033[30m"
#define RED "\033[31m"
#define GREEN "\033[32m"              /* Green */
#define YELLOW "\033[33m"             /* Yellow */
#define BLUE "\033[34m"               /* Blue */
#define MAGENTA "\033[35m"            /* Magenta */
#define CYAN "\033[36m"               /* Cyan */
#define WHITE "\033[37m"              /* White */
#define BOLDBLACK "\033[1m\033[30m"   /* Bold Black */
#define BOLDRED "\033[1m\033[31m"     /* Bold Red */
#define BOLDGREEN "\033[1m\033[32m"   /* Bold Green */
#define BOLDYELLOW "\033[1m\033[33m"  /* Bold Yellow */
#define BOLDBLUE "\033[1m\033[34m"    /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m" /* Bold Magenta */
#define BOLDCYAN "\033[1m\033[36m"    /* Bold Cyan */
#define BOLDWHITE "\033[1m\033[37m"   /* Bold White */
#define RESET "\033[0m"
#define BLACK "\033[30m"   /* Black */
#define RED "\033[31m"     /* Red */
#define GREEN "\033[32m"   /* Green */
#define YELLOW "\033[33m"  /* Yellow */
#define BLUE "\033[34m"    /* Blue */
#define MAGENTA "\033[35m" /* Magenta */
#define CYAN "\033[36m"    /* Cyan */
#define CA_CERT_FILE "./ca-bundle.crt"
const int BLOCKSIZE = 8192 * 0.73; //* 0.7;
char Block[BLOCKSIZE] = {0};
string Cache = "Cache/";
using namespace std;
SHA256 hasher;
Datadedup DD = Datadedup(Cache);
long GetFileSize(std::string filename)
{
    struct stat64 stat_buf;
    int rc = stat64(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}
long FdGetFileSize(int fd)
{
    struct stat64 stat_buf;
    int rc = fstat64(fd, &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}
bool exist(httplib::Client &cli, string filename)
{
    if (exists(Cache + filename))
    {
        return 1;
    }
    auto res = cli.Get("/exists/" + filename);
    if (res)
    {
        if (strcmp(res->body.c_str(), "0") == 0)
            return 0;
    }
    else
        return NULL;
    return 1;
}
map<string, int> sent;
void DDWrite(httplib::Client &cli, string filename)
{
    // return;
    long filesize = GetFileSize(filename);

    ifstream F(filename);
    ofstream hashs(Cache + "/" + filename + ".hashs");
    string C;
    string Hash;
    int blocks = -1;
    int equalcount = 0;
    // cout << endl;
    time_t CE;
    time(&CE);
    while (!F.eof())
    {
        blocks++;
        // cout<<endl;
        cout << BOLDGREEN << "\r[ " << RESET; //<<blocks<<"/"<<filesize/BLOCKSIZE;
        equalcount = 0;
        for (double i = 0; i <= ((double)blocks * BLOCKSIZE / (double)filesize); i += 0.019)
        {
            cout << GREEN << "=";
            equalcount++;
        }
        for (int i = equalcount; i < 50; i++)
        {
            cout << YELLOW << "=";
        }
        // cout<<time(0)<<endl;
        try
        {
            cout << BOLDGREEN << " ] " << blocks << "/" << filesize / BLOCKSIZE << " " << blocks / (time(0) - CE + 0.1) * BLOCKSIZE / 1004 / 1000 * 8 << "Mb/S" << RESET;
        }
        catch (exception e)
        {
            cout << time(0) << endl;
        }
        // cout << BOLDGREEN << " ] " << blocks << "/" << filesize / BLOCKSIZE << " " << RESET;

        // std::streamsize s = ((F) ? BLOCKSIZE : F.gcount());
        hasher.init();
        F.read(Block, BLOCKSIZE);
        C = Block;
        // cout<<"\n/append/" + filename + "/" + sha256(C)<<endl;
        // sleep(2);
        cli.Get("/append/" + b64encode(filename) + "/" + sha256(C) + ",");
        DD.write_packet(b64encode(C), sha256(C));
        if (!sent[sha256(C)])
            if (!exist(cli, sha256(C)))
            {

                cli.Get("/write/" + sha256(C) + "/" + b64encode(C));
                sent[sha256(C)] = 1;
            }
            else
                sent[sha256(C)] = 1;
        else
            sent[sha256(C)]++;

        hashs << sha256(C) << ",";
        for (int i = 0; i < BLOCKSIZE; i++)
            Block[i] = 0;
    }
    F.close();
    hashs.close();
    cout << "done" << endl;
}
string removebranch(string pathfile)
{
    return pathfile.substr(pathfile.find_last_of("/\\") + 1);
}
vector<string> hashs;
void DDRead_Step2(httplib::Client &cli, ofstream &file)
{
    int blocks = -1;
    int equalcount = 0;
    time_t C;
    time(&C);
    for (int i = 0; i < hashs.size(); i++)
    {
        blocks++;
        // cout<<endl;
        cout << BOLDGREEN << "\r[ " << RESET; //<<blocks<<"/"<<filesize/BLOCKSIZE;
        // cout<<endl;
        equalcount = 0;
        for (double i = 0; i <= ((double)blocks / (double)hashs.size()); i += 0.019)
        {
            cout << GREEN << "=";
            equalcount++;
        }
        for (int i = equalcount; i < 50; i++)
        {
            cout << YELLOW << "=";
        }
        // cout<<time(0)<<endl;
        try
        {
            cout << BOLDGREEN << " ] " << blocks << "/" << hashs.size() << " " << blocks / (time(0) - C + 0.1) * BLOCKSIZE / 1004 / 1000 * 8 << "Mb/S" << RESET;
        }
        catch (exception e)
        {
            cout << time(0) << endl;
        }
        // cout<<Cache+hashs[i]<<" -> "<<exists(Cache+hashs[i])<<endl;
        if (exists(Cache + hashs[i]))
        {
            file << b64decode(DD.read_packet(hashs[i]));
        }
        else
        {
            auto res = cli.Get("/read/" + hashs[i]);
            if (res)
            {
                // cout << sha256(b64decode(res->body)) << " <=>" << hashs[i] << endl;
                file << b64decode(res->body).c_str();
            }
            else
            {
                cout << "error" << endl;
            }
        }
    }
}
void gethashs_step2(string hashssepcomma)
{
    hashs.clear();
    string buffer;
    try
    {
        for (int i = 0; i < hashssepcomma.size(); i++)
        {
            if (hashssepcomma[i] == ',')
                hashs.push_back(buffer), buffer = "";
            else
                buffer.push_back(hashssepcomma[i]);
            // cout<<hashssepcomma[i]<<endl;
        }
    }
    catch (exception e)
    {
        cout << "error getting hashs step 2" << endl;
    }
}
void gethashs(string hashfile)
{

    ifstream hashsfile(hashfile);
    stringstream ss;
    ss << hashsfile.rdbuf();
    string hashssepcomma = ss.str();
    gethashs_step2(hashssepcomma);
    hashsfile.close();
    // return hashs;
}
void DDRead(httplib::Client &cli, vector<string> &hashs, string filename)
{
    ofstream file(removebranch(filename));
    // cout << removebranch(filename) << endl;
    DDRead_Step2(cli, file);
    file.close();
}
void DDRead(httplib::Client &cli, string filename)
{
    cout << removebranch(filename) << endl;
    ofstream file(filename);
    auto res = cli.Get("/download/" + b64encode(filename));
    if (res)
    {
        // cout << res->body << endl;
        gethashs_step2(res->body);
    }
    else
    {
        cout << "error" << endl;
    }
    DDRead_Step2(cli, file);

    file.close();
}
void DDlist(httplib::Client &cli)
{
    auto res = cli.Get("/list");
    if (res)
        gethashs_step2(res->body);
    // cout<<res->body<<endl;
}
class Commandlineinterface
{
public:
    Commandlineinterface()
    {
    }
    void Ls(httplib::Client &cli)
    {
        DDlist(cli);
        for (int i = 0; i < hashs.size(); i++)
        {
            cout << b64decode(hashs[i]) << endl;
        }
    }
    void Stat(httplib::Client &cli)
    {
        cout << cli.Get("/stat/")->body << endl;
    }
    void Upload_Folder(httplib::Client &cli, string folder)
    {
        for (const auto &p : std::filesystem::recursive_directory_iterator(folder))
        {
            if (!std::filesystem::is_directory(p))
            {
                this->Upload(cli, p.path()), cout << p.path() << endl;
            }
        }
    }
    void Download_Folder(httplib::Client &cli, string folder)
    {
        for (const auto &p : std::filesystem::recursive_directory_iterator(folder))
        {
            if (!std::filesystem::is_directory(p))
            {
                this->Download(cli, p.path()), cout << p.path() << endl;
            }
        }
    }
    void Upload(httplib::Client &cli, string filename)
    {
        auto res = cli.Get("/remove/" + b64encode(filename));
        DDWrite(cli, filename);
    }
    void Download(httplib::Client &cli, string filename)
    {
        DDRead(cli, filename);
    }
    void Remove(httplib::Client &cli, string filename)
    {
        auto res = cli.Get("/remove/" + b64encode(filename));
    }
    long Size(httplib::Client &cli, string filename)
    {
        auto res = cli.Get("/download/" + b64encode(filename));
        // cout<<res->body<<endl;
        if (res)
        {
            gethashs_step2(res->body);
            cout << hashs.size() << "blocks of " << BLOCKSIZE << " char long" << endl;
            return hashs.size();
        }
        else
        {
            cout << "no connection to server" << endl;
        }
        return 0;
    }
};
string replacecharparchar(string s, char in, char out)
{
    // cout<<"rpcpc: "<<s<<endl;
    string buffer = "";
    for (int i = 0; i < s.size(); i++)
        if (s[i] == out)
            buffer.push_back(in);
        else
            buffer.push_back(s[i]);
    return buffer;
}
int irclastsize = 0;
string hostname;
vector<string> global_argv;
#include <unistd.h>
#include <termios.h>

char getch()
{
    char buf = 0;
    struct termios old = {0};
    if (tcgetattr(0, &old) < 0)
        perror("tcsetattr()");
    old.c_lflag &= ~ICANON;
    old.c_lflag &= ~ECHO;
    old.c_cc[VMIN] = 1;
    old.c_cc[VTIME] = 0;
    if (tcsetattr(0, TCSANOW, &old) < 0)
        perror("tcsetattr ICANON");
    if (read(0, &buf, 1) < 0)
        perror("read()");
    old.c_lflag |= ICANON;
    old.c_lflag |= ECHO;
    if (tcsetattr(0, TCSADRAIN, &old) < 0)
        perror("tcsetattr ~ICANON");
    return (buf);
}
string s = "";
int _x=0;
int _y=0;
bool mousemode=0;
void Chat_client(string mode, httplib::Client &client)
{
    int _lasty=0;
    string buff = "";
    if (strcmp(mode.c_str(), "rtc") == 0)
    {
        int lasts_size = 0;
        while (true)
        {
            auto resd = client.Get("/download/irc/");
            gethashs_step2(resd->body);
            if (hashs.size() != irclastsize || _lasty!=_y)
            {_lasty=_y;
                lasts_size = s.size();
                system("clear");
                irclastsize = hashs.size();
                for (int i = 0; i < hashs.size(); i++)
                {
                    if(_x==0){
                        if(i==hashs.size()-_y)cout<<BOLDMAGENTA;
                    }
                    cout << b64decode(client.Get("/read/" + hashs[i] + "/")->body)<<RESET << "\r";
                }
                cout << "\r"
                     << " ->" << s;
            }
            else
            {
                cout << "\r"
                     << "-->" << s <<" xy: "<<_x<<","<<_y<< std::flush;
            }

#include <chrono>
#include <thread>

            std::this_thread::sleep_for(std::chrono::milliseconds(270));
        }
    }
    if (strcmp(mode.c_str(), "irc") == 0)
    {

        char c;
        char lastc;
        
        while (true)
        {
            // cin.getline(Buff, 1024);
            s = "";
            while (c != '\n')
            {
                c = getch();
                //cout<<(int)c<<endl;
                if(c==127)
                s.pop_back();
                else if(lastc==91){
                    if(mousemode){
                        if(c==65){
                            _y++;
                        }
                        if(c==66){
                            _y--;
                        }
                        if(c==68){
                            _x--;
                        }
                        if(c==67){
                            _x++;
                        }
                    }
                }
                else if(c==9){
                    mousemode=!mousemode;
                }
                else if(c!=91)
                s.push_back(c);
                
                
                lastc=c;
            }
            c = '\0';
            buff = s;
            client.Get("/write/" + sha256(hostname + " : " + buff) + "/" + b64encode(hostname + " : " + buff) + "/");
            client.Get("/append/irc/" + sha256(hostname + " : " + buff) + ",/");
        }
    }
}
int main(int argc, char **argv)
{
    DD = Datadedup(Cache);
    hasher = SHA256();
    string buff = "";
    char Buff[1024];
    for (int i = 0; i < argc; i++)
        global_argv.push_back(argv[i]);
    if (argc < 2)
    {
        cout << "usage Client ip port" << endl;
        exit(0);
    }
    else if (argc >= 3)
    {
        for (int i = 3; i < argc; i++)
        {
            buff += argv[i];
            buff += " ";
        }
    }
    int fu = 0;
    try
    {
        fu = stoi(argv[2]);
    }
    catch (exception e)
    {
        cout << "port must be of type int!" << endl;
        exit(0);
    }
    httplib::Client client(argv[1], fu);
    hostname = argv[1];
    Commandlineinterface cli;
    auto res = client.Get("/hi");
    if (!res)
    {
        cout << "server did not respond" << endl;
        exit(0);
    }

    cout << "usage: Upload,Download,Remove\",\"filename Ls exist but dosnt need any param" << endl;
    try
    {
        while (true)
        {
            cout << "\n->";
            // cin >> buff;
            if (!(argc >= 4))
            {
                cin.getline(Buff, 1024);
                buff = Buff;
            }
            // cout << replacecharparchar(buff, ',', ' ') << endl;
            gethashs_step2(replacecharparchar(buff, ',', ' ') + ",,");
            // cout<<"parsed"<<endl;
            for (int i = 0; i < hashs.size(); i++)
            {

                if (strcmp(hashs[i].c_str(), "Upload") == 0)
                {
                    cli.Upload(client, hashs[i + 1]);
                }
                if (strcmp(hashs[i].c_str(), "Download") == 0)
                {
                    cli.Download(client, hashs[i + 1]);
                }
                if (strcmp(hashs[i].c_str(), "Ls") == 0)
                {
                    cli.Ls(client);
                }
                if (strcmp(hashs[i].c_str(), "stat") == 0)
                {
                    cli.Stat(client);
                }
                if (strcmp(hashs[i].c_str(), "Backup") == 0)
                {
                    cli.Upload_Folder(client, hashs[i + 1]);
                }
                if (strcmp(hashs[i].c_str(), "new") == 0)
                {
                    client.Get("/new/" + hashs[i + 1] + "/" + hashs[i + 2] + "/");
                }
                if (strcmp(hashs[i].c_str(), "delete") == 0)
                {
                    client.Get("/delete/" + hashs[i + 1] + "/");
                }

                if (strcmp(hashs[i].c_str(), "Size") == 0)
                {
                    cli.Size(client, hashs[i + 1]);
                }
                if (strcmp(hashs[i].c_str(), "Remove") == 0)
                {
                    cli.Remove(client, hashs[i + 1]);
                }
                if (strcmp(hashs[i].c_str(), "stop") == 0)
                {
                    client.Get("/stop/");
                    // cli.Remove(client, hashs[i + 1]);
                }
                if (strcmp(hashs[i].c_str(), "connect") == 0)
                {
                    string a = "./Client-bin " + hashs[i + 1] + " " + hashs[i + 2];
                    system(a.c_str());
                    client.Get("/bye");
                    cout << "disconected" << endl;
                    return 0;
                    // cli.Remove(client, hashs[i + 1]);
                }
                if (strcmp(hashs[i].c_str(), "exit") == 0)
                {
                    client.Get("/bye");
                    cout << "disconected" << endl;
                    return 0;
                }
                if (strcmp(hashs[i].c_str(), "restore") == 0)
                {
                    cli.Upload_Folder(client, hashs[i + 1]);
                }
                if (strcmp(hashs[i].c_str(), "reload") == 0)
                {
                    client.Get("/bye");
                    client.stop();
                    cout << "Rebuilding client.." << endl;
                    system("sh Client.sh");
                    // cout << "disconected" << endl;
                    return 0;
                }

                if (strcmp(hashs[i].c_str(), "chat") == 0)
                {
                    string s = string(global_argv[0] + " " + global_argv[1] + " " + global_argv[2] + " irc");
                    hostname = hashs[i + 1];
                    thread t(Chat_client, string("irc"), std::ref(client));

                    thread t2(Chat_client, string("rtc"), std::ref(client));
                    t.join();
                    t2.join();
                }
            }
            if (argc >= 4)
                exit(0);
        }
    }
    catch (exception e)
    {
    }

    return 0;
}