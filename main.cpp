#include "pk_change.h"

int main(int argc, char *argv[])
{
    if(check(argc,argv) == false) exit(1);
    //get own macaddress
    NetworkInterface iface(sd_dev);
    NetworkInterface::Info info;
    info = iface.addresses();
    mac = info.hw_addr;
    cout<<"send dev :"<<sd_dev<<"\n";
    cout<<"mac address :"<<mac<<"\n";
    //wireless sniffing
    pk_set ps;
    ps.image_f(1);//jpeg
    ps.image_f(2);//png
    ps.sf_set();
}
