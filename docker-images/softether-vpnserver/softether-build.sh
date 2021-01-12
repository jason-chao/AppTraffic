#!/usr/bin/env sh

# link object code
cd /tmp/install/vpnserver
make i_read_and_agree_the_license_agreement
cd ..

# move the vpnserver to /usr/local
mv /tmp/install/vpnserver /usr/local
cd /usr/local/vpnserver/

# set the permissions for SoftEther files
chmod 600 *

# set the permissions for vpnserver and vpncmd which are executables
chmod 700 vpnserver
chmod 700 vpncmd

exit 0
