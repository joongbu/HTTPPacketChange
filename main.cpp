#include <tins/tins.h>
#include <tins/tcp_ip/stream_follower.h>
#include <iostream>
#include <arpa/inet.h>
using namespace Tins;
using namespace std;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;
struct foo {
    void bar() {
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("port 80");
        config.set_promisc_mode(true);
        Sniffer sniffer("eth0", config);
        sniffer.sniff_loop(make_sniffer_handler(this, &foo::handle));

    }
    void send(EthernetII ethernet, IP ip, TCP tcp, RawPDU raw)
    {

        PacketSender sender;
        EthernetII pkt = EthernetII(ethernet.src_addr(),ethernet.dst_addr()) / IP(ip.src_addr(),ip.dst_addr()) / TCP(tcp.sport(),tcp.dport()) / RawPDU(raw);
        sender.send(pkt, "eth0");
    }

    bool handle(PDU& pdu) {
        const EthernetII &ethernet = pdu.rfind_pdu<EthernetII>();
        const IP &ip = pdu.rfind_pdu<IP>();
        const TCP &tcp = pdu.rfind_pdu<TCP>();

        if(tcp.dport() == 80)
        {
            const RawPDU& raw = tcp.rfind_pdu<RawPDU>();
            const RawPDU::payload_type& payload = raw.payload();
            uint32_t new_seq = 0;
            new_seq = tcp.seq() + tcp.header_size(); //여기서 23이라는 16진수가 더해져야한다.

            //send(ethernet,ip,tcp,raw);
            cout<<"ethernet :"<<ethernet.src_addr()<<" / "<<ethernet.dst_addr()<<endl;
            cout<<"IP src :"<<ip.src_addr()<<" / "<<ip.dst_addr()<<endl;
            cout<<"Tcp port :"<<tcp.sport()<<" / "<<tcp.dport()<<endl;
            cout<<"tcp.seq num : "<<hex<<tcp.seq()<<endl;
            cout<<"tpc.ack num : "<<hex<<tcp.ack_seq()<<endl;
            cout<<"header size :" <<hex<<tcp.header_size()<<endl;
            cout<<"flag : "<<hex<<tcp.flags()<<endl;
            cout<<"new_seq num :"<<hex<<new_seq<<endl;
            cout<<payload.data()<<endl;



        }

        return true;
    }
};



int main() {

    foo f;
    f.bar();


}
