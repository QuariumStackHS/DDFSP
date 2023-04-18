

find . -name "*.o" -type f -print0 | xargs -0 /bin/rm -f
#find . -name "*.SHA1" -type f -print0 | xargs -0 /bin/rm -f
#find . -name "*.uc" -type f -print0 | xargs -0 /bin/rm -f
./Client-bin localhost 8080 Backup src ;
cd src;sh build_dependencies.sh; cd ../