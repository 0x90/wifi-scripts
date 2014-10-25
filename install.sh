#!/bin/sh
#TODO: test it!

print_status(){
    echo -e "\x1B[01;34m[*]\x1B[0m $1"
}

ask(){
    while true; do
        if [ "${2:-}" = "Y" ]; then
            prompt="Y/n"
            default=Y
        elif [ "${2:-}" = "N" ]; then
            prompt="y/N"
            default=N
        else
            prompt="y/n"
            default=
        fi

        read -p "$1 [$prompt] " REPLY
        if [ -z "$REPLY" ]; then
            REPLY=$default
        fi

        case "$REPLY" in
            Y*|y*) return 0 ;;
            N*|n*) return 1 ;;
        esac
    done
}

pause(){
   read -sn 1 -p "Press any key to continue..."
}

check_euid(){
    print_status "Checking for root privs."
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be ran with sudo or root privileges, or this isn't going to work."
	    exit 1
    else
        print_good "w00t w00t we are root!"
    fi
}


# apt-get install wireless-tools
apt-get install linux-headers-$(uname -r) build-essential make patch subversion openssl libssl-dev zlib1g zlib1g-dev libssh2-1-dev libnl1 libnl-dev gettext autoconf tcl8.5 libpcap0.8 libpcap0.8-dev python-scapy python-dev cracklib-runtime macchanger-gtk tshark ethtool iw


if ask "Install horst?" Y; then
    git clone git://br1.einfach.org/horst /tmp/horst
    cd /tmp/horst
    make
    cp horst /usr/bin
    cd /tmp
    rm -rf horst
fi

# GNU Radio 802.11
# An IEEE 802.11 a/g/p Transceiver  http://www.ccs-labs.org/projects/wime/
# git clone https://github.com/bastibl/gr-ieee802-11

if ask "Install scapy?" Y; then
    print_status "Installing Scapy dependencies"
    apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx wireshark -y

    #pip install -e hg+https://bb.secdev.org/scapy#egg=scapy --insecure
    cd /tmp
    hg clone https://bb.secdev.org/scapy --insecure
    cd scapy
    ./setup.py install

    #Cleanup
    cd ..
    rm -rf scapy/*
    rm -rf scapy/.hg*
    rmdir scapy
fi

if ask "Install scapytain?" N; then
    apt-get install -y python-cherrypy3 graphviz python-genshi python-sqlobject python-formencode python-pyopenssl highlight python-trml2pdf python-pip
    # pip install   http://www.satchmoproject.com/snapshots/trml2pdf-1.2.tar.gz
    pip install pyopenssl

    #pip install -e hg+ --insecure
    # udo pip install -e hg+http://bb.secdev.org/scapytain#egg=scapytain --insecure
    cd /tmp
    hg clone https://bb.secdev.org/scapytain --insecure
    cd scapytain
    ./setup.py install

    mcedit /etc/scapytainrc
    mkdir /var/lib/scapytain
    scapytain_dbutil -c

    #Cleanup
    cd /tmp
    rm -rf scapytain/*
    rm -rf scapytain/.hg*
    rmdir scapytain
fi

# Latest version of Pylorcon2 https://github.com/tom5760/pylorcon2
if ask "Install Lorcon?" Y; then
    print_status "Installing Lorcon dependecies"
    apt-get install libpcap0.8-dev libnl-dev

    #Requires lorcon
    print_status "Installing Lorcon"
    cd /usr/src
    git clone https://code.google.com/p/lorcon
    cd lorcon
    ./configure
    make && make install

    # install pylorcon2
    print_status "Install pylorcon2"
    cd /usr/src
    svn checkout http://pylorcon2.googlecode.com/svn/trunk/ pylorcon2
    cd pylorcon2
    python setup.py build
    python setup.py install
fi

if ask "Install aircrack-nf from source?" Y; then
    cd /tmp
    git clone https://github.com/aircrack-ng/aircrack-ng
    cd /tmp/aircrack-ng
    #wget http://patches.aircrack-ng.org/channel-negative-one-maxim.patch
    #patch -p1 < channel-negative-one-maxim.patch
    make
    make install
    cd scripts/airgraph-ng
    python setup.py install
    #ln -s /usr/local/bin/airgraph-ng /usr/share/airgraph-ng
    mkdir /usr/share/airgraph-ng
fi
