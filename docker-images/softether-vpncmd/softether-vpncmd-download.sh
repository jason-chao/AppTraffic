#!/usr/bin/env sh

cd /tmp/install

# download and decompress Softether
wget https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v4.32-9731-beta/softether-vpnclient-v4.32-9731-beta-2020.01.01-linux-x64-64bit.tar.gz
gzip -d softether-vpnclient-v4.32-9731-beta-2020.01.01-linux-x64-64bit.tar.gz
tar -xvf softether-vpnclient-v4.32-9731-beta-2020.01.01-linux-x64-64bit.tar

exit 0
