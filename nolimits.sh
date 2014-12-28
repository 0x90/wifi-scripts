#!/bin/sh

card=$1

#1st Method.
iw reg set BO
iwconfig $card  txpower 30

#2nd Method.
ifconfig $card down
iw reg set BO
ifconfig $card up
iwconfig $card channel 13
iwconfig $card txpower 30
