#include <tins/tins.h>
#include <iostream>
#include <arpa/inet.h>
#include <algorithm>
using namespace Tins;
using namespace std;
struct pk_set {
    void sf_set() {
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("port 80");
        config.set_promisc_mode(true);
        Sniffer sniffer("eth0", config);
        sniffer.sniff_loop(make_sniffer_handler(this, &pk_set::handle));

    }
    void debug(EthernetII ethernet, IP ip, TCP tcp)
    {
        cout<<"ethernet<src /dst> :"<<ethernet.src_addr()<<" / "<<ethernet.dst_addr()<<endl;
        cout<<"IP src<src /dst> :"<<ip.src_addr()<<" / "<<ip.dst_addr()<<endl;
        cout<<"Tcp port<src /dst> :"<<tcp.sport()<<" / "<<tcp.dport()<<endl;
        cout<<"tcp.seq num : "<<hex<<tcp.seq()<<endl;
        cout<<"tpc.ack num : "<<hex<<tcp.ack_seq()<<endl;

    }

    void send(EthernetII ethernet, IP ip, TCP tcp,RawPDU::payload_type payload)
    {
        uint32_t new_seq, new_ack;
        EthernetII new_ethernet = ethernet;
        new_ethernet.src_addr(ethernet.dst_addr());
        new_ethernet.dst_addr(ethernet.src_addr());
        IP new_ip = ip;
        //swap
        new_ip.src_addr(ip.dst_addr());
        new_ip.dst_addr(ip.src_addr());
        TCP new_tcp = tcp;
        //swap
        new_tcp.sport(tcp.dport());
        new_tcp.dport(tcp.sport());
        new_seq = new_tcp.ack_seq(); // caclulator
        new_ack = new_tcp.seq() + payload.size(); //caclulator
        new_tcp.seq(new_seq);
        new_tcp.ack_seq(new_ack);
        cout<<"header size : "<<new_tcp.header_size()<<endl;
        //debug
        debug(new_ethernet,new_ip,new_tcp);
        /*
        PacketSender sender;
        EthernetII attack = new_ethernet / new_ip / new_tcp;
        sender.send(attack, "eth0");
        */

    }

    bool handle(PDU& pdu) {
        const EthernetII &ethernet = pdu.rfind_pdu<EthernetII>();
        const IP &ip = pdu.rfind_pdu<IP>();
        const TCP &tcp = pdu.rfind_pdu<TCP>();

        if(tcp.dport() == 80)
        {
            const RawPDU& raw = tcp.rfind_pdu<RawPDU>();
            const RawPDU::payload_type& payload = raw.payload();\
            send(ethernet,ip,tcp,payload);

            //debug(ethernet,ip,tcp);



        }

        return true;
    }
};



int main() {

    pk_set ps;
    ps.sf_set();


}
