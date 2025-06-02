/**
 * @file
 * @brief DUT 상태 관련 기능을 구현한 파일
 * @date 2019-09-25
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#include "j29451/j29451.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"

#if defined(_LTEV2X_HAL_)
/**
 * @brief 송신 플로우 정보를 초기화 한다.
 */
void TCIA2023_InitTxFlowInfo(void)
{
  Log(kTCIA3LogLevel_Event, "Initialize transmit flow info\n");
  g_tcia_mib.flow_info[0].index = kLTEV2XHALTxFLowIndex_Default;
  g_tcia_mib.flow_info[0].type = kLTEV2XHALTxFlowType_Default;
  g_tcia_mib.flow_info[0].interval = kLTEV2XHALTxFLowInterval_Default;
  g_tcia_mib.flow_info[0].power = kLTEV2XHALPower_Default;
  g_tcia_mib.flow_info[0].pppp = kLTEV2XHALPriority_Default;
  g_tcia_mib.flow_info[0].size = kLTEV2XHALMSDUSize_Default;
  g_tcia_mib.flow_info[1].index = kLTEV2XHALTxFLowIndex_Default;
  g_tcia_mib.flow_info[1].type = kLTEV2XHALTxFlowType_Default;
  g_tcia_mib.flow_info[1].interval = kLTEV2XHALTxFLowInterval_Default;
  g_tcia_mib.flow_info[1].power = kLTEV2XHALPower_Default;
  g_tcia_mib.flow_info[1].pppp = kLTEV2XHALPriority_Default;
  g_tcia_mib.flow_info[1].size = kLTEV2XHALMSDUSize_Default;
  g_tcia_mib.flow_info[2].index = kLTEV2XHALTxFLowIndex_Default;
  g_tcia_mib.flow_info[2].type = kLTEV2XHALTxFlowType_Default;
  g_tcia_mib.flow_info[2].interval = kLTEV2XHALTxFLowInterval_Default;
  g_tcia_mib.flow_info[2].power = kLTEV2XHALPower_Default;
  g_tcia_mib.flow_info[2].pppp = kLTEV2XHALPriority_Default;
  g_tcia_mib.flow_info[2].size = kLTEV2XHALMSDUSize_Default;

  LTEV2XHAL_DeleteTransmitFlow(kLTEV2XHALTxFLowIndex_SPS1);
  LTEV2XHAL_DeleteTransmitFlow(kLTEV2XHALTxFLowIndex_SPS2);
}
#endif

/**
 * @brief WSM 송수신정보를 초기화한다.
 *
 * @param[out] wsm_trx_info 초기화할 WSM 송수신정보 구조체 포인터
 */
static void TCIA2023_InitWSMTrxInfo(struct TCIA3WSMTrxInfo *info)
{
  Log(kTCIA3LogLevel_Event, "Initialize WSM tx info\n");
  memset(info, 0, sizeof(struct TCIA3WSMTrxInfo));
  info->if_idx = 0;
  info->chan_num_ext = false;
  info->datarate_ext = false;
  info->txpower_ext = false;
  info->psid = kDot3PSID_NA;
  info->chan_num = kDot3ChannelNumber_NA;
  info->timeslot = kDot3TimeSlot_NA;
  info->datarate = kDot3DataRate_TxDefault;
  info->tx_power = kDot3Power_TxDefault;
  info->priority = kDot3Priority_Max;
  info->repeat_rate = 0;
  memset(info->dst_mac_addr, 0xff, MAC_ALEN);
  info->pdu_size = 0;
  info->txing = false;
}


/**
 * @brief 테스트 관련 정보를 초기화한다.
 */
static void TCIA2023_InitTestingInfo(void)
{
  Log(kTCIA3LogLevel_Event, "Initialize DUT state info\n");
  g_tcia_mib.testing.testing = false;
  g_tcia_mib.testing.test_protocol = kTCIA3TestProtocol_NA;
  g_tcia_mib.testing.auto_bsm_tx = g_tcia_mib.input_params.auto_bsm_tx;
  for (int i = 0; i < 3; i++) {
    g_tcia_mib.testing.pkt_cnt.tx_wsm[i] = 0;
    g_tcia_mib.testing.pkt_cnt.rx_wsm[i] = 0;
  }
  g_tcia_mib.testing.pkt_cnt.tx_wsa = 0;
}


/**
 * @brief WSA 정보를 초기화한다.
 */
static void TCIA2023_InitWSAInfo(struct TCIA3WSAInfo *info)
{
  Log(kTCIA3LogLevel_Event, "Initialize WSA info\n");
  memset(info, 0, sizeof(struct TCIA3WSAInfo));

  // 송신정보 초기화
  struct TCIA3WSATxInfo *tx_info = &(info->tx_info);
  tx_info->if_idx = 0;
  tx_info->chan_num = kDot3ChannelNumber_NA;
  tx_info->timeslot = kDot3TimeSlot_NA;
  tx_info->datarate = kDot3DataRate_TxDefault;
  tx_info->tx_power = kDot3Power_TxDefault;
  tx_info->priority = kDot3Priority_Max;
  tx_info->repeat_rate = 0;
  memset(tx_info->dst_mac_addr, 0xff, MAC_ALEN);
  tx_info->txing = false;

  // 헤더정보 초기화
  struct TCIA3WSAHdrInfo *hdr_info = &(info->hdr_info);
  hdr_info->options.repeat_rate = false;
  hdr_info->options.twod_location = false;
  hdr_info->options.threed_location = false;
  hdr_info->options.advertiser_id = false;
  hdr_info->content_count = 0;
  hdr_info->advertiser_id.len = 0;
  memset(hdr_info->advertiser_id.id, 0, sizeof(hdr_info->advertiser_id.id));
  hdr_info->latitude = g_tcia_mib.input_params.lat;
  hdr_info->longitude = g_tcia_mib.input_params.lon;
  hdr_info->elevation = g_tcia_mib.input_params.elev;
  hdr_info->repeat_rate = DEFAULT_REPEAT_RATE;

  // 보안정보 초기화
  struct TCIA3WSASecurityInfo *sec_info = &(info->sec_info);
  sec_info->content_type = kCvcoctci2023ContentType_Ieee16092Data;
  sec_info->signer_id_type = kCvcoctci2023SignerIdentifierType_UseSecProfilePerContentType;

  // WRA 정보 초기화
  struct TCIA3WRAInfo *wra_info = &(info->wra_info);
  wra_info->options.secondary_dns = false;
  wra_info->options.wra = false;
  wra_info->options.gw_mac_addr = false;
  wra_info->router_lifetime = 0;
  memset(wra_info->ip_prefix, 0, IPv6_ALEN);
  wra_info->ip_prefix_len = 0;
  memset(wra_info->default_gw, 0, IPv6_ALEN);
  memset(wra_info->primary_dns, 0, IPv6_ALEN);
  memset(wra_info->secondary_dns, 0, IPv6_ALEN);
  memset(wra_info->gw_mac_addr, 0, MAC_ALEN);

  Log(kTCIA3LogLevel_Event, "Delete all PSRs\n");
  Dot3_DeleteAllPSRs();
}


/**
 * @brief IP 네트워킹 정보를 초기화한다.
 * @param[out] ip_net_info 초기화할 IP 네트워킹 정보 구조체 포인터
 */
static void TCIA2023_InitIPNetworkingInfo(struct TCIA3IPNetworkingInfo *ip_net_info)
{
  for (unsigned int if_idx = 0; if_idx < g_tcia_mib.v2x_if.if_num; if_idx++) {
    TCIA2023_DeleteAllIPv6Address(if_idx);
#if defined(_TCIA2023_DSRC_)
    WAL_SetAutoLinkLocalIPv6Address(if_idx);
#endif
  }
  memset(ip_net_info, 0, sizeof(struct TCIA3IPNetworkingInfo));
}


/**
 * @brief DUT를 초기 상태로 설정한다.
 */
void TCIA2023_InitDUTState(void)
{
  Log(kTCIA3LogLevel_Event, "Initialize DUT state\n");

  // BSM 송신 동작을 중지한다.
  J29451_StopBSMTransmit();

  /**
   * Update TCIv3 by young@KETI
   * BSM 송신 동작을 중지하고 txing 파라미터를 false로 변경한다.
   * J29451 BSM를 송신은 pthread를 사용하지 않기때문에 
   * */
  if (g_tcia_mib.wsm_trx_info[kDot3TimeSlot_Continuous].j29451_bsm_txing == true) {
    g_tcia_mib.wsm_trx_info[kDot3TimeSlot_Continuous].j29451_bsm_txing = false;
  }

  // WSM 송신 동작을 중지한다.
  TCIA2023_StopWSMTransmit(0); // TimeSlot0(Alternating)
  TCIA2023_StopWSMTransmit(1); // TimeSlot1(Alternating)
  TCIA2023_StopWSMTransmit(2); // Continuous
  
  // WSM 수신 동작을 중지한다.
  TCIA2023_StopWSMReceive(0); // TimeSlot0(Alternating)
  TCIA2023_StopWSMReceive(1); // TimeSlot1(Alternating)
  TCIA2023_StopWSMReceive(2); // Continuous

  // WSA 송신 동작을 중지한다.
  TCIA2023_StopWSATransmit();

  // Ping 송신 동작을 중지한다.
  TCIA2023_StopPingTxOperation();

  // UDP 송수신 동작을 중지한다.
  TCIA2023_StopUDPTxOperation();
  TCIA2023_StopUDPRxOperation();

  // WSM 송수신정보를 초기화한다.
  TCIA2023_InitWSMTrxInfo(&(g_tcia_mib.wsm_trx_info[0])); // TimeSlot0(Alternating)
  TCIA2023_InitWSMTrxInfo(&(g_tcia_mib.wsm_trx_info[1])); // TimeSlot1(Alternating)
  TCIA2023_InitWSMTrxInfo(&(g_tcia_mib.wsm_trx_info[2])); // Continuous

  // WSA 송신정보를 초기화한다.
  TCIA2023_InitWSAInfo(&(g_tcia_mib.wsa_info));

  // IP 네트워킹 정보를 초기화한다.
  TCIA2023_InitIPNetworkingInfo(&(g_tcia_mib.ip_net_info));

  // 테스트 관련 정보를 초기화한다.
  TCIA2023_InitTestingInfo();

#if defined(_TCIA2023_DSRC_)
  // 각 인터페이스를 160번 채널에 접속한다. (테스트 중이 아닌 인터페이스로 패킷이 수신되는 것을 방지하기 위해)
  for (unsigned int if_idx = 0; if_idx < g_tcia_mib.v2x_if.if_num; if_idx++) {
    WAL_AccessChannel(if_idx, DEFAULT_IF_CHAN_NUM, DEFAULT_IF_CHAN_NUM);
    WAL_DeleteTxProfile(if_idx);
  }
#endif

  /*
   * 등록되어 있는 USR 및 UAS들을 모두 삭제한다.
   */
  Dot3_DeleteAllUSRs();
  Dot3_DeleteAllUASs();
}


/**
 * @brief 현재 테스트 중인 프로토콜 유형을 저장한다.
 * @param[in] frame_type TCI 프레임 유형
 */
void TCIA2023_SetTestProtocol(Cvcoctci2023TciFrameType frame_type)
{
  switch (frame_type) {
    /**
     * Update TCIv3 by young@KETI
     * 16093 rename to 16093dsrc
     * */
    case kCvcoctci2023FrameType_16093Dsrc:
      Log(kTCIA3LogLevel_Event, "Set test protocol - 1609.3\n");
      g_tcia_mib.testing.test_protocol = kTCIA3TestProtocol_16093dsrc;
      break;
    case kCvcoctci2023FrameType_80211:
      Log(kTCIA3LogLevel_Event, "Set test protocol - 802.11\n");
      g_tcia_mib.testing.test_protocol = kTCIA3TestProtocol_80211;
      break;
    case kCvcoctci2023FrameType_16094:
      Log(kTCIA3LogLevel_Event, "Set test protocol - 1609.4\n");
      g_tcia_mib.testing.test_protocol = kTCIA3TestProtocol_16094;
      break;
    case kCvcoctci2023FrameType_29451:
      Log(kTCIA3LogLevel_Event, "Set test protocol - 29451\n");
      g_tcia_mib.testing.test_protocol = kTCIA3TestProtocol_29451;
      break;
    case kCvcoctci2023FrameType_16093Cv2x:
      Log(kTCIA3LogLevel_Event, "Set test protocol - 16093cv2x\n");
      g_tcia_mib.testing.test_protocol = kTCIA3TestProtocol_16093pc5;
      break;
    case kCvcoctci2023FrameType_31611:
      Log(kTCIA3LogLevel_Event, "Set test protocol - 31611\n");
      g_tcia_mib.testing.test_protocol = kTCIA3TestProtocol_31611;
      break;
    case kCvcoctci2023FrameType_SutControl:
    default:
      break;
  }
}
