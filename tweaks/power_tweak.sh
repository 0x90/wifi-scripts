#!/bin/sh

# 13 channel
ifconfig wlan0 down
iw wlan0 reg set BO
ifconfig wlan0 up
iwconfig wlan0 channel 13

# Power1
ifconfig wlan0 down
iw reg set BO
iwconfig wlan0 txpower 500mW

# Power2
iwconfig wlan0 txpower 30
ifconfig wlan0 up
