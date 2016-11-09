LINUX 


install : libtins

git clone https://github.com/mfontanini/libtins.git

apt-get install libpcap-dev libssl-dev cmake

mkdir build

cd build

cmake ../

make

make install

ldconfig

install : dot11decrypt

git clone https://github.com/mfontanini/dot11decrypt

/////////////////////////////////////////////////////

Sniffer sniffer(iface, 2500, false);

code 수정

////////////////////////////////////////////////////

   SnifferConfiguration config;
    
   config.set_promisc_mode(true);
    
   config.set_immediate_mode(true);
    
   Sniffer sniffer(iface,config);
    
/////////////////////////////////////////////////////    

mkdir build

cd build

cmake ..

make

usage : ./dot11decrypt wlan0 wpa:MyAccessPoint:some_password
사용법

dot11decrypt 실행 -> HTTPChange (monitor mode adapter) (send adapter) (jpeg path) 실ㅇ해
