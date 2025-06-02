#!/bin/bash

# User settings
COMM=lte-v2x   # dsrc, lte-v2x
DEV_NAME=/dev/spidev1.1
TCI_PORT=13001
IF0_MAC_ADDR=00:01:02:03:04:05
IF1_MAC_ADDR=00:01:02:03:04:06
IF0_RCPI_CORRECTION=5
IF1_RCPI_CORRECTION=6
LAT=374065375
LON=1271017772
ELEV=0
AUTO_BSM_TX=0
BSM_REPLAY=0
#CMHF_DIR=certificates/cmhf/app  # for RSU test
CMHF_DIR=certificates/cmhf/pseudonym  # for OBU test
RCA_CERT=certificates/scc/rca
ICA_CERT=certificates/scc/ica
PCA_CERT=certificates/scc/pca
DBG=4    # 0:none, 1:err, 2:init, 3:event, 4:detailed event, 5:pkt dump
LIBCVCOCTCI_DBG=1
LIBDOT2_DBG=1
LIBDOT3_DBG=1
LIBJ29451_DBG=1
LIBLTEACCESS_DBG=1
LIBWLANACCESS_DBG=1

## Configure IP interface
#IF0_IP_NAME=llc-cch-ipv6
#IF1_IP_NAME=llc-sch-ipv6
#ip link set dev $IF0_IP_NAME address $IF0_MAC_ADDR
#ip link set dev $IF0_IP_NAME up
#ip link set dev $IF1_IP_NAME address $IF1_MAC_ADDR
#ip link set dev $IF1_IP_NAME up

## Run tcia
if [ "$AUTO_BSM_TX" == "1" ] && [ "$BSM_REPLAY" == "1" ]; then
  ./app/tcia-2023 start --dev $DEV_NAME --port $TCI_PORT --addr0 $IF0_MAC_ADDR --addr1 $IF1_MAC_ADDR --rcpi0 $IF0_RCPI_CORRECTION --rcpi1 $IF1_RCPI_CORRECTION \
  --lat $LAT --lon $LON --elev $ELEV --autobsm --replay --cmhfdir $CMHF_DIR --rca $RCA_CERT --ica $ICA_CERT --pca $PCA_CERT --dbg $DBG \
  --tcidbg $LIBCVCOCTCI_DBG --dot2dbg $LIBDOT2_DBG --dot3dbg $LIBDOT3_DBG --j29451dbg $LIBJ29451_DBG --lteaccessdbg $LIBLTEACCESS_DBG \
  --wlanaccessdbg $LIBWLANACCESS_DBG
elif [ "$AUTO_BSM_TX" == "1" ] && [ "$BSM_REPLAY" == "0" ]; then
  ./app/tcia-2023 start --dev $DEV_NAME --port $TCI_PORT --addr0 $IF0_MAC_ADDR --addr1 $IF1_MAC_ADDR --rcpi0 $IF0_RCPI_CORRECTION --rcpi1 $IF1_RCPI_CORRECTION \
  --lat $LAT --lon $LON --elev $ELEV --autobsm --cmhfdir $CMHF_DIR --rca $RCA_CERT --ica $ICA_CERT --pca $PCA_CERT --dbg $DBG \
  --tcidbg $LIBCVCOCTCI_DBG --dot2dbg $LIBDOT2_DBG --dot3dbg $LIBDOT3_DBG --j29451dbg $LIBJ29451_DBG --lteaccessdbg $LIBLTEACCESS_DBG \
  --wlanaccessdbg $LIBWLANACCESS_DBG
elif [ "$AUTO_BSM_TX" == "0" ] && [ "$BSM_REPLAY" == "1" ]; then
  ./app/tcia-2023 start --dev $DEV_NAME --port $TCI_PORT --addr0 $IF0_MAC_ADDR --addr1 $IF1_MAC_ADDR --rcpi0 $IF0_RCPI_CORRECTION --rcpi1 $IF1_RCPI_CORRECTION \
  --lat $LAT --lon $LON --elev $ELEV --replay --cmhfdir $CMHF_DIR --rca $RCA_CERT --ica $ICA_CERT --pca $PCA_CERT --dbg $DBG \
  --tcidbg $LIBCVCOCTCI_DBG --dot2dbg $LIBDOT2_DBG --dot3dbg $LIBDOT3_DBG --j29451dbg $LIBJ29451_DBG --lteaccessdbg $LIBLTEACCESS_DBG \
  --wlanaccessdbg $LIBWLANACCESS_DBG
else
  ./app/tcia-2023 start --dev $DEV_NAME --port $TCI_PORT --addr0 $IF0_MAC_ADDR --addr1 $IF1_MAC_ADDR --rcpi0 $IF0_RCPI_CORRECTION --rcpi1 $IF1_RCPI_CORRECTION \
  --lat $LAT --lon $LON --elev $ELEV --cmhfdir $CMHF_DIR --rca $RCA_CERT --ica $ICA_CERT --pca $PCA_CERT --dbg $DBG --tcidbg $LIBCVCOCTCI_DBG \
  --dot2dbg $LIBDOT2_DBG --dot3dbg $LIBDOT3_DBG --j29451dbg $LIBJ29451_DBG --lteaccessdbg $LIBLTEACCESS_DBG \
  --wlanaccessdbg $LIBWLANACCESS_DBG
fi