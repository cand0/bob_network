#!/bin/bash

old="wlx909f330f328e"

ifconfig $old down
ip link set $old name mon0
iwconfig mon0 mode monitor
ifconfig mon0 up
