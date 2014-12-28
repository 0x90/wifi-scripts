#!/bin/sh

#1st Method.
iw reg set BO
iwconfig wlan0 txpower 30

#2nd Method.
ifconfig wlan0 down
iw reg set BO
ifconfig wlan0 up
iwconfig wlan0 channel 13
iwconfig wlan0 txpower 30
