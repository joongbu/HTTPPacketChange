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

mkdir build

cd build

cmake ..

make

usage : ./dot11decrypt wlan0 wpa:MyAccessPoint:some_password
