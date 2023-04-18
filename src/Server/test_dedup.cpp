
#include "Dedupmf.hpp"

int main(){
    Datadedup DD("Storage/");
    DD.write_packet(b64encode("enormous string of a limited amount"),"0");
    //DD.read_packet()
}