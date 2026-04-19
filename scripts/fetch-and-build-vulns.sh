#!/usr/bin/env bash

cd /tmp
wget https://github.com/libexpat/libexpat/releases/download/R_2_2_9/expat-2.2.9.tar.gz
tar xzf expat-2.2.9.tar.gz
cd expat-2.2.9

./configure --prefix=${VULN_DIR} CFLAGS="-g"
make -j$(nproc)
sudo make install

cd /tmp
wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1f.tar.gz
tar xzf openssl-1.1.1f.tar.gz
cd openssl-1.1.1f

./config --prefix=${VULN_DIR} \
         --openssldir=${VULN_DIR}/ssl \
         -g \
         shared          # build .so so uprobes can attach
make -j$(nproc)
sudo make install

