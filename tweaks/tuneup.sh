#!/usr/bin/env bash

#To configure a WiFi interface for sniffing, use the following (traditional) commands:
#ifconfig wlan0 down
#iwconfig wlan0 mode monitor
#iwconfig wlan0 channel 6
#ifconfig wlan0 up

#or alternatively the newer ones:
#ip link set wlan0 down
#iw dev wlan0 set type monitor
#ip link set wlan0 up
#iw dev wlan0 set channel 6

iface="mon0"
channel=$1
bssid=$2
#bssid="c0:4a:00:6e:d8:fa"
#channel=11

#http://www.embeddedcircle.com/wi-fi-filter-for-wireshark/

iwconfig ${iface} channel ${channel}
#tshark -R "wlan.fc.type_subtype eq 8 and wlan.bssid eq ${bssid}" -i ${iface} \
# -T fields -e wlan.bssid -e radiotap.datarate -e radiotap.antenna -e radiotap.dbm_antsignal -e radiotap.datarate

tshark  -i ${iface} -T fields -E header=y -np \
 -e frame.time_relative -e wlan_mgt.ssid -e wlan.bssid -e wlan.seq -e radiotap.dbm_antsignal \
  -e radiotap.antenna -e radiotap.datarate -e radiotap.dbm_antnoise \
  -Y "wlan.fc.type_subtype == 8 and wlan.bssid == ${bssid}"

