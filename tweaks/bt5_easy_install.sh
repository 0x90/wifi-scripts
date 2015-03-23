#!/bin/sh

GNOME_MENU_ENTRY="/usr/share/applications/backtrack-eapeak.desktop"

echo "Installing Mercurial..."
apt-get -y install mercurial 2>&1 > /dev/null

echo "Installing Dependency M2Crypto..."
apt-get -y install m2crypto 2>&1 > /dev/null

echo "Installing Dependency Argparse..."
hg clone http://code.google.com/p/argparse 2>&1 > /dev/null
cd argparse
python setup.py build 2>&1 > /dev/null
python setup.py install 2>&1 > /dev/null
cd ..
rm -rf argparse

echo "Replacing Scapy with the Community Edition..."
if [ -f "/usr/bin/scapy" ]; then
	rm /usr/bin/scapy 2>&1 > /dev/null
fi
if [ -d "/usr/lib/pymodules/python2.6/scapy" ]; then
	rm -rf /usr/lib/pymodules/python2.6/scapy 2>&1 > /dev/null
fi
hg clone http://hg.secdev.org/scapy-com 2>&1 > /dev/null
cd scapy-com
python setup.py build 2>&1 > /dev/null
python setup.py install 2>&1 > /dev/null
cd ..
rm -rf scapy-com

echo "Installing EAPEAK..."
if [ -d "/pentest/wireless/eapeak" ]; then
	rm -rf /pentest/wireless/eapeak 2>&1 > /dev/null
fi
hg clone http://code.google.com/p/eapeak /pentest/wireless/eapeak 2>&1 > /dev/null
pushd /pentest/wireless/eapeak 2>&1 > /dev/null
python setup.py build 2>&1 > /dev/null
python setup.py install 2>&1 > /dev/null
rm -rf build
popd 2>&1 > /dev/null

echo "[Desktop Entry]" > $GNOME_MENU_ENTRY
echo "Name=eapeak" >> $GNOME_MENU_ENTRY
echo "Encoding=UTF-8" >> $GNOME_MENU_ENTRY
echo "Exec=sh -c \"cd /pentest/wireless/eapeak ;eapeak;sudo -s\"" >> $GNOME_MENU_ENTRY
echo "Icon=btmenu.png" >> $GNOME_MENU_ENTRY
echo "StartupNotify=false" >> $GNOME_MENU_ENTRY
echo "Terminal=true" >> $GNOME_MENU_ENTRY
echo "Type=Application" >> $GNOME_MENU_ENTRY
echo "Categories=bt-network-analysis-wireless-lan;" >> $GNOME_MENU_ENTRY

if [ -f "/usr/share/applications/desktop.en_US.utf8.cache" ]; then
	rm /usr/share/applications/desktop.en_US.utf8.cache 2>&1 > /dev/null
fi
killall gnome-panel 2>&1 > /dev/null

echo "Done."
