/** 
 * @file
 * @brief
 * @date 2021-03-08
 * @author gyun
 */


#ifndef V2X_SW_TCIA2023_FUNCS_H
#define V2X_SW_TCIA2023_FUNCS_H


// 시스템 헤더 파일
#include <stddef.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#if defined(_TCIA2023_LTE_V2X_)
#if defined(_LTEV2X_HAL_)
#include "ltev2x-hal/ltev2x-hal.h"
#else
#include "lteaccess/lteaccess.h"
#endif
#endif

// 어플리케이션 헤더 파일
#include "tcia2023-types.h"


#if defined(_TCIA2023_DSRC_)
// dsrc/tcia-dsrc.c
void TCIA2023_DSRC_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size, Dot3TimeSlot timeslot);
void TCIA2023_DSRC_TransmitWSA(const uint8_t *secured_wsa, size_t secured_wsa_size);
void TCIA2023_DSRC_ProcessRxMPDUCallback(const uint8_t *mpdu, WalMPDUSize mpdu_size, const struct WalMPDURxParams *mpdu_rx_params);
int TCIA2023_DSRC_AccessChannel(unsigned int if_idx, WalChannelNumber ts0_chan, WalChannelNumber ts1_chan);
int TCIA2023_DSRC_SetInitialIfMACAddress(void);
#endif

// ipv6/tcia-ipv6-addr.c
int TCIA2023_SetRandomLinkLocalAddress(unsigned int if_idx);
int TCIA2023_DeleteAllIPv6Address(unsigned int if_idx);

// ipv6/tcia-ipv6-icmp.c
int TCIA2023_StartPingTxOperation(const struct Cvcoctci2023StartIPv6Ping *data);
void TCIA2023_StopPingTxOperation(void);

// ipv6/tcia-ipv6-rx.c
void TCIA2023_StopUDPRxOperation(void);
int TCIA2023_StartIPv6RxOperation(const struct Cvcoctci2023StartIPv6Rx *data);
int TCIA2023_StopIPv6RxOperation(const struct Cvcoctci2023StopIPv6Rx *data);

// ipv6/tcia-ipv6-tx.c
void TCIA2023_StopUDPTxOperation(void);
int TCIA2023_StartIPv6TxOperation(const struct Cvcoctci2023StartIPv6Tx *data, const uint8_t *payload, size_t payload_size);
int TCIA2023_StopIPv6TxOperation(const struct Cvcoctci2023StopIPv6Tx *data);

#if defined(_TCIA2023_LTE_V2X_)
// lte-v2x/tcia-lte-v2x.c
void TCIA2023_LTE_V2X_InitTerminateHandler(void);
#if defined(_LTEV2X_HAL_)
int TCIA2023_LTE_V2X_RegisterTransmitFlow(LTEV2XHALTxFlowIndex index, LTEV2XHALPriority priority, LTEV2XHALTxFlowInterval tx_interval, LTEV2XHALMSDUSize size);
#else
int TCIA2023_LTE_V2X_RegisterTransmitFlow(Dot3PSID psid, LalPower power, LalPriority priority, unsigned int tx_interval);
#endif
void TCIA2023_LTE_V2X_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size, Dot3TimeSlot timeslot);
void TCIA2023_LTE_V2X_TransmitWSA(const uint8_t *secured_wsa, size_t secured_wsa_size);
#if defined(_LTEV2X_HAL_)
void TCIA2023_LTE_V2X_TransmitBSM(const uint8_t *secured_bsm, size_t secured_bsm_size, Dot3TimeSlot timeslot, bool event);
#endif
#if defined(_LTEV2X_HAL_)
void TCIA2023_LTE_V2X_ProcessRxMSDUCallback(const uint8_t *msdu, LTEV2XHALMSDUSize msdu_size, struct LTEV2XHALMSDURxParams rx_params);
#else
void TCIA2023_LTE_V2X_ProcessRxMSDUCallback(const uint8_t *msdu, size_t msdu_size);
#endif
#endif

// ts-if/ts-if.c
int TCIA2023_InitTestSystemInterfaceFunction(uint16_t port);
void TCIA2023_SendTCIMessagePacket(const uint8_t *pkt, size_t pkt_size);

// ts-if/ts-if-indication.c
int TCIA2023_ConstructIndication(const uint8_t *mpdu, size_t mpdu_size, const uint8_t *wsm, size_t wsm_size, const struct WalMPDURxParams *mpdu_rx_params, const struct Dot3MACAndWSMParseParams *wsm_mpdu_parse_params, const struct Dot3ParseWSAParams *wsa_parse_params, Cvcoctci2023SecurityResultCode result_code, uint8_t *outbuf, size_t outbuf_size);
int TCIA2023_ConstructIndication_ICMPv6PktRx(unsigned int if_idx, uint8_t *src_ipv6_addr, uint8_t *ip_pkt, size_t ip_pkt_size, uint8_t *outbuf, size_t outbuf_size);
int TCIA2023_ConstructIndication_UDPPktRx(unsigned int if_idx, uint8_t *src_ipv6_addr, uint8_t *ip_payload, size_t ip_payload_size, uint8_t *outbuf, size_t outbuf_size);

// ts-if/ts-if-process-tci.c
int TCIA2023_ProcessTCIMessage(const struct Cvcoctci2023Params *parse_params, const uint8_t *pdu, size_t pdu_size, Cvcoctci2023Radio *radio_idx);
int TCIA2023_ProcessSetInitialState(bool data);
int TCIA2023_ProcessEnableGpsInput(bool data);
int TCIA2023_ProcessSetLatitude(Cvcoctci2023SetLatitude data);
int TCIA2023_ProcessSetLongitude(Cvcoctci2023SetLongitude data);
int TCIA2023_ProcessSetElevation(Cvcoctci2023SetElevation data);
int TCIA2023_ProcessSetPositionalAccuracy(const struct Cvcoctci2023SetPositionalAccuracy *data);
int TCIA2023_ProcessSetSpeed(Cvcoctci2023SetSpeed data);
int TCIA2023_ProcessSetHeading(Cvcoctci2023SetHeading data);
int TCIA2023_ProcessSetAccelerationSet4Way(const struct Cvcoctci2023SetAccelerationSet4Way *data);
int TCIA2023_ProcessSetGpsTime(Cvcoctci2023SetGpsTime data);
int TCIA2023_ProcessSetWsmTxInfo(const struct Cvcoctci2023SetWsmTxInfo *data);
int TCIA2023_ProcessStartWsmTx(const struct Cvcoctci2023StartWsmTx *data, const uint8_t *pdu, size_t pdu_size);
int TCIA2023_ProcessPc5StartWsmTx(const struct Cvcoctci2023Pc5StartWsmTx *data, const uint8_t *pdu, size_t pdu_size);
int TCIA2023_ProcessStopWsmTx(const struct Cvcoctci2023StopWsmTx *data);
int TCIA2023_ProcessStartWsmRx(const struct Cvcoctci2023StartWsmRx *data);
int TCIA2023_ProcessStopWsmRx(const struct Cvcoctci2023StopWsmRx *data);
int TCIA2023_ProcessSendUeConfigXML(const struct Cvcoctci2023SendUeConfigXML *data);
int TCIA2023_ProcessSetUeConfig(const struct Cvcoctci2023SetUeConfig *data);
int TCIA2023_ProcessSetFlowConfigs(const struct Cvcoctci2023SetFlowConfigs *data);
int TCIA2023_ProcessSendATCommand(const struct Cvcoctci2023SendATCommand *data);
int TCIA2023_ProcessRequestSutStatus(const bool data);

// ts-if/ts-if-process-tci16093dsrc.c
int TCIA2023_Process16093DSRCTCIMessage(const struct Cvcoctci2023Params *parse_params, const uint8_t *pdu, size_t pdu_size, Cvcoctci2023Radio *radio_idx);

/**
 * Update TCIv3 by young@KETI
 * Add TCI16093PC5
 * ts-if/ts-if-process-tci16093pc5.c
 * */
int TCIA2023_Process16093PC5TCIMessage(const struct Cvcoctci2023Params *parse_params, const uint8_t *pdu, size_t pdu_size, Cvcoctci2023Radio *radio_idx);

// ts-if/ts-if-process-tci16094.c
int TCIA2023_Process16094TCIMessage(const struct Cvcoctci2023Params *parse_params, const uint8_t *pdu, size_t pdu_size);

// ts-if/ts-if-process-tci29451.c
int TCIA2023_Process29451TCIMessage(const struct Cvcoctci2023Params *parse_params);

// ts-if/ts-if-process-tci31611.c
int TCIA2023_Process31611TCIMessage(const struct Cvcoctci2023Params *parse_params);

// ts-if/ts-if-process-tci80211.c
int TCIA2023_Process80211TCIMessage(const struct Cvcoctci2023Params *parse_params, const uint8_t *pdu, size_t pdu_size);

// ts-if/ts-if-process-tcisutctrl.c
int TCIA2023_ProcessSutControlTCIMessage(const struct Cvcoctci2023Params *parse_params);

// ts-if/ts-if-response.c
void TCIA2023_ConstructAndSendTCIResponse(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result);
void TCIA2023_ConstructAndSendTCIResponseInterfaceInfo(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result, Cvcoctci2023Radio radio_idx);
void TCIA2023_ConstructAndSendTCIResponseSutInfo(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result);
void TCIA2023_ConstructAndSendTCIResponseAtCmdInfo(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result, size_t at_cmd_size, uint8_t *at_cmd);
void TCIA2023_ConstructAndSendTCIResponsePacketCount(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result, size_t pkt_count);
void TCIA2023_ConstructAndSendTCIResponseSutStatus(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result);

// tcia-bsm.c
int TCIA2023_StartBSMTransmit(void);
void TCIA2023_BSMTransmitCallback(const uint8_t *bsm, size_t bsm_size, bool event, bool cert_sign, bool id_change, uint8_t *addr);

// tcia-dut-state.c
void TCIA2023_InitDUTState(void);
void TCIA2023_InitTxFlowInfo(void);
void TCIA2023_SetTestProtocol(Cvcoctci2023TciFrameType frame_type);

// tcia-input-params.c
int TCIA2023_ParseInputParameters(int argc, char *argv[]);

// tcia-interface.c
int TCIA2023_GetInterfaceNameForIndex(unsigned int if_idx, char *if_name);
int TCIA2023_GetInterfaceInfo(Cvcoctci2023Radio radio_idx, struct Cvcoctci2023IPv6InterfaceInfos *infos);

// tcia-log.c
void TCIA2023_PrintLog(const char *func, const char *format, ...);
void TCIA2023_PrintPacketDump(TCIALogLevel log_level, const uint8_t *pkt, size_t pkt_size);

// tcia-security.c
int TCIA2023_InitSecurity(void);
void TCIA2023_ProcessSPDUCallback(Dot2ResultCode result, void *priv);

// tcia-wra.c
int TCIA2023_ProcessRxWRA(unsigned int if_idx, struct Dot3WRA *wra);

// tcia-wsa.c
int TCIA2023_ConstructWSA(uint8_t *outbuf);
int TCIA2023_StartWSATransmit(void);
void TCIA2023_StopWSATransmit(void);
int TCIA2023_ProcessRxWSA(unsigned int if_idx, const uint8_t *wsa, size_t wsa_size, Dot3MACAddress src_mac_addr, Dot3WSAType wsa_type, Dot3RCPI rcpi, Dot3Latitude tx_lat, Dot3Longitude tx_lon, Dot3Elevation tx_elev, struct Dot3ParseWSAParams *params);

// tcia-wsm.c
int TCIA2023_StartWSMTransmit(Dot3TimeSlot timeslot);
void TCIA2023_StopWSMTransmit(Dot3TimeSlot timeslot);
void TCIA2023_StartWSMReceive(Dot3TimeSlot timeslot);
void TCIA2023_StopWSMReceive(Dot3TimeSlot timeslot);

#endif //V2X_SW_TCIA2023_FUNCS_H
