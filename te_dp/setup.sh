#!/bin/sh
apt-get update  # To get the latest package lists
cd /tmp/
apt-get install automake libtool m4 -y
apt-get install libjson0 libjson0-dev -y
apt-get build-dep curl
apt-get install build-essential nghttp2 libnghttp2-dev libssl-dev -y

#OPENSSL 1.1.1a
wget https://www.openssl.org/source/openssl-1.1.1a.tar.gz
tar -zxf openssl-1.1.1a.tar.gz && rm openssl-1.1.1a.tar.gz
cd openssl-1.1.1a
./config && make -j8 && make install
mv /usr/bin/openssl ~/tmp
ln -s /usr/local/bin/openssl /usr/bin/openssl
ldconfig

#ZeroMQ
echo "deb http://download.opensuse.org/repositories/network:/messaging:/zeromq:/release-stable/Debian_9.0/ ./" >> /etc/apt/sources.list
wget https://download.opensuse.org/repositories/network:/messaging:/zeromq:/release-stable/Debian_9.0/Release.key -O- | sudo apt-key add
apt-get install -y libzmq3-dev

#LIBCURL
wget https://curl.haxx.se/download/curl-7.67.0.tar.gz
tar -xvf curl-7.67.0.tar.gz
cd curl-7.67.0
#./configure --with-nghttp2 --prefix=/usr/local --with-ssl=/usr/local/ssl
#For openssl 1.1.1 support (TLSv1.3)
./configure --with-nghttp2 --prefix=/usr/local --with-default-ssl-backend=openssl
make -j8
make install
ldconfig
cd /tmp/
rm -rf curl*

#LIBUV
wget https://dist.libuv.org/dist/v1.27.0/libuv-v1.27.0.tar.gz
tar xvf libuv-v1.27.0.tar.gz
cd libuv-v1.27.0/
./autogen.sh
./configure
make -j8
make install
cd /tmp/
rm -rf libuv*
ldconfig
