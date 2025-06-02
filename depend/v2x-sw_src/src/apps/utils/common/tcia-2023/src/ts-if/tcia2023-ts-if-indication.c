/**
 * @file
 * @brief TCI 메시지를 생성하는 기능을 구현한 파일
 * @date 2019-09-25
 * @author gyun
 */

// 시스템 헤더 파일
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#if defined(_LTEV2X_HAL_)
#include "dot3-2016/dot3.h"
#else
#include "dot3/dot3.h"
#endif

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * Updated by young@KETI
 * 기존에 pdu_type에서 d80211frame, d16093frame이 사라지고 d16093payload로 대체
 *
 * @brief TS로 전송할 Indication 메시지를 생성한다.
 * @param[in] mpdu 수신된 V2X MPDU
 * @param[in] mpdu_size 수신된 V2X MPDU의 크기
 * @param[in] wsm 수신된 V2X MPDU 내 WSM 시작 지점
 * @param[in] wsm_size WSM의 크기
 * @param[in] mpdu_rx_params MPDU 수신 정보가 저장되어 있는 정보구조체 포인터
 * @param[in] wsm_parse_params WSM MPDU 파싱 정보가 저장되어 있는 정보구조체 포인터
 * @param[in] wsa_parse_params WSA 파싱 정보가 저장되어 있는 정보구조체 포인터
 * @param[in] result_code 서명 검증 결과
 * @param[out] outbuf 생성된 Indication 메시지가 저장/반환될 버퍼
 * @param[in] outbuf_size outbuf 버퍼의 크기
 * @retval 양수: 생성된 Indication 메시지의 크기 (성공)
 * @retval -1: 실패
 */
int TCIA2023_ConstructIndication(
  const uint8_t *mpdu,
  size_t mpdu_size,
  const uint8_t *wsm,
  size_t wsm_size,
  const struct WalMPDURxParams *mpdu_rx_params,
  const struct Dot3MACAndWSMParseParams *wsm_mpdu_parse_params,
  const struct Dot3ParseWSAParams *wsa_parse_params,
  Cvcoctci2023SecurityResultCode result_code,
  uint8_t *outbuf,
  size_t outbuf_size)
{
  Log(kTCIA3LogLevel_DetailedEvent, "Construct Indication\n");

  /*
   * PSID에 해당되는 시간슬롯을 확인한다.
   */
  Dot3TimeSlot timeslot;
#if defined(_TCIA2023_DSRC_)
  if (wsm_mpdu_parse_params->wsm.psid == g_tcia_mib.wsm_trx_info[0].psid) {
    timeslot = kDot3TimeSlot_0;
  } else if (wsm_mpdu_parse_params->wsm.psid == g_tcia_mib.wsm_trx_info[1].psid) {
    timeslot = kDot3TimeSlot_1;
  } else if (wsm_mpdu_parse_params->wsm.psid == g_tcia_mib.wsm_trx_info[2].psid) {
    timeslot = kDot3TimeSlot_Continuous;
  } else {
    timeslot = kDot3TimeSlot_Continuous;
    Err("Fail to construct Indication - cannot find timeslot for psid %d\n", wsm_mpdu_parse_params->wsm.psid);
    return -1;
  }
#elif defined(_TCIA2023_LTE_V2X_)
  timeslot = kDot3TimeSlot_Continuous;
#endif

  struct Cvcoctci2023Indication ind_params = CVCOCTCI2023_INDICATION_CONSTRUCT_PARAMS_INITIALIZER;
  struct Cvcoctci2023EventHandling *event_handling = &(g_tcia_mib.wsm_trx_info[timeslot].event_handling); // StartWsmRx에 의해 설정된 정보

  /*
   * StartWsmRx에 의해 설정된 바에 따라 Indication 메시지 내 옵션 필드 수납을 결정한다.
   */
#if defined(_TCIA2023_DSRC_)
  ind_params.radio = mpdu_rx_params->if_idx;
#elif defined(_TCIA2023_LTE_V2X_)
  ind_params.radio.radio = V2I_V2V_IF_IDX;
#else
#error "Communication type is not defined"
#endif

  /*
   * 테스트 프로토콜(정확히는 테스트장비)에 따라 Indication 정보를 설정한다.
   *  802.11: Keysight
   *  1609.x: Spirent
   * 테스트장비에 따라 해석의 차이가 존재한다.
   */
  if (g_tcia_mib.testing.test_protocol == kTCIA3TestProtocol_80211) {
    ind_params.options.event_params = true;
    ind_params.options.pdu = true;
    ind_params.event_params_type = kCvcoctci2023EventParamsType_radioframe;
  } else {
    if (event_handling->rx_flag.include_pdu_param == true) { ind_params.options.event_params = true; }
    if (event_handling->rx_flag.include_pdu == true) { ind_params.options.pdu = true; }
    if (event_handling->options.event_params_choice == true) {ind_params.options.event_params = true; }
    ind_params.event_params_type = event_handling->event_params_choice;
  }

  if (event_handling->rx_flag.recv_psid_match == true) {
    if (wsm_mpdu_parse_params->wsm.psid != g_tcia_mib.wsm_trx_info[timeslot].psid) {
      Err("Fail to construct Indication - cannot find timeslot for psid %d\n", wsm_mpdu_parse_params->wsm.psid);
      return -1;
    }
  }

  /*
   * StartWsmRx에 설정된 바에 따라 Indication 메시지 내에 Event Parameters 및 Pdu를 삽입한다.
   */
  if (ind_params.options.event_params == true)
  {
    switch (ind_params.event_params_type)
    {
      case kCvcoctci2023EventParamsType_Service:
        ind_params.event = kCvcoctci2023Event_Dot3RequestMatchedAvailAppService;
        ind_params.event_params.service.psid_cnt = wsa_parse_params->wsi_num;
        Log(kTCIA3LogLevel_DetailedEvent, "Construct Indication for Service event - psid num: %u\n",
            ind_params.event_params.service.psid_cnt);
        for (unsigned int i = 0; i < ind_params.event_params.service.psid_cnt; i++) {
          ind_params.event_params.service.psid[i] = wsa_parse_params->wsis[i].psid;
          Log(kTCIA3LogLevel_DetailedEvent, "  [%d] psid : %d\n", i, ind_params.event_params.service.psid[i]);
        }

        if (ind_params.options.pdu == true) {
          /**
           * Update TCIv3 by young@KETI
           * Remove kCvcoctci2023PduType_16093frame. DEPRECATED. Use d16093payload instead
           *
           * */
          ind_params.pdu.pdu_type = kCvcoctci2023PduType_16093payload;
          ind_params.pdu.pdu_data = (uint8_t *)wsm;
          ind_params.pdu.pdu_data_size = wsm_size;
        }
        break;

      case kCvcoctci2023EventParamsType_Wsm:
        Log(kTCIA3LogLevel_DetailedEvent, "Construct Indication for WsmPktRx event\n");
        ind_params.event = kCvcoctci2023Event_WsmPktRx;
        ind_params.event_params.wsm.psid = wsm_mpdu_parse_params->wsm.psid;
        ind_params.event_params.wsm.radio.radio = ind_params.radio.radio;
        ind_params.event_params.wsm.wsmp_version = wsm_mpdu_parse_params->wsm.version;
        /**
         * Update TCIv3 by young@KETI
         * chan_id change to OPTIONAL
         * */
        ind_params.event_params.wsm.options.chan_id = true;
        ind_params.event_params.wsm.chan_id = mpdu_rx_params->chan_num;
        /**
         * Update TCIv3 by young@KETI
         * datarate change to OPTIONAL
         * */
        ind_params.event_params.wsm.options.datarate = true;
        ind_params.event_params.wsm.datarate = mpdu_rx_params->datarate;
        /**
         * Update TCIv3 by young@KETI
         * rx_power_level change to OPTIONAL
         * */
        ind_params.event_params.wsm.options.rx_power_level = true;
        ind_params.event_params.wsm.rx_power_level = mpdu_rx_params->rx_power;
        /**
         * Update TCIv3 by young@KETI
         * src_mac_addr change to OPTIONAL
         * */
        ind_params.event_params.wsm.options.src_mac_addr = true;
        memcpy(ind_params.event_params.wsm.src_mac_addr, wsm_mpdu_parse_params->mac.src_mac_addr, MAC_ALEN);
        /**
         * Update TCIv3 by young@KETI
         * Add rssi OPTIONAL
         * */
#if defined(_TCIA2023_LTE_V2X_)
        ind_params.event_params.wsm.options.rssi = true;
        ind_params.event_params.wsm.rssi = (int)mpdu_rx_params->rcpi;
#endif
        if (ind_params.options.pdu == true) {
          /**
           * Update TCIv3 by young@KETI
           * Remove kCvcoctci2023PduType_16093frame. DEPRECATED. Use d16093payload instead
           *
           * */
          ind_params.pdu.pdu_type = kCvcoctci2023PduType_16093payload;
          ind_params.pdu.pdu_data = (uint8_t *)wsm;
          ind_params.pdu.pdu_data_size = wsm_size;
        }
        break;
      /**
       * Update TCIv3 by young@KETI
       * kCvcoctci2023EventParamsType_80211frame rename to kCvcoctci2023EventParamsType_radioframe
       * */
      case kCvcoctci2023EventParamsType_radioframe:
        Log(kTCIA3LogLevel_DetailedEvent, "Construct Indication for 80211PktRx event\n");
        ind_params.event = kCvcoctci2023Event_RadioPktRx;

        /**
         * Update TCIv3 by young@KETI
         * d80211frame rename to radioframe
         * */
        ind_params.event_params.radioframe.radio.radio = (int) mpdu_rx_params->if_idx;
        ind_params.event_params.radioframe.rcpi = (int) mpdu_rx_params->rcpi;
        if (true == ind_params.options.pdu) {
          /**
           * Update TCIv3 by young@KETI
           * Remove kCvcoctci2023PduType_80211frame. DEPRECATED. Use d16093payload instead
           * */
          ind_params.pdu.pdu_type = kCvcoctci2023PduType_16093payload;
          ind_params.pdu.pdu_data = (uint8_t *)mpdu;
          ind_params.pdu.pdu_data_size = mpdu_size;
        }
        break;

      case kCvcoctci2023EventParamsType_Security:
        ind_params.event = kCvcoctci2023Event_Dot2VerificationCompleteWithResult;
        if (result_code == kCvcoctci2023SecurityResultCode_Success) {
          ind_params.event_params.security.sec_result_code = kCvcoctci2023TciResultCode_Success;
          Log(kTCIA3LogLevel_DetailedEvent, "Construct Indication for security result : success\n");
        } else {
          ind_params.event_params.security.sec_result_code = kCvcoctci2023TciResultCode_Failure;
          Log(kTCIA3LogLevel_DetailedEvent, "Construct Indication for security result : fail\n");
        }

        if (ind_params.options.pdu == true) {
          /**
           * Update TCIv3 by young@KETI
           * Remove kCvcoctci2023PduType_16093frame. DEPRECATED. Use d16093payload instead
           * */
          ind_params.pdu.pdu_type = kCvcoctci2023PduType_16093payload;
          ind_params.pdu.pdu_data = (uint8_t *)mpdu;
          ind_params.pdu.pdu_data_size = mpdu_size;
        }
        if (g_tcia_mib.testing.test_protocol == kTCIA3TestProtocol_80211) {
          // TODO:: for Keysight TS
          // Spirent TS 에서는 kCvcoctci2023Event_Dot2VerificationCompleteWithResult인 경우 PDU를 전달하지 않아도 되었으나,
          // Keysight TS 에서는 요구하고 있다. - 근데 PDU를 받기 원한다면 StartBsmRx Request 에서 event_handling->rx_flag.include_pdu를
          // set 해서 보냈어야 하지 않나?? 보내지 않았다.

        }
        break;

      case kCvcoctci2023EventParamsType_Ip:
        Err("Fail to construct indication - Not supported event parameter type %d\n", ind_params.event_params_type);
        break;

      default:
        Err("Fail to construct indication - event parameter type %d\n", ind_params.event_params_type);
        return -1;
    }
  }

  /*
   * 테스트 중인 프로토콜 유형에 따라 Indication 메시지를 생성한다.
   */
  int pkt_size;
  switch (g_tcia_mib.testing.test_protocol) {
    case kTCIA3TestProtocol_16093dsrc:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16093DSRC Indication\n");
      pkt_size = Cvcoctci2023_Construct16093DsrcIndication(&ind_params, outbuf, outbuf_size);
      break;
    case kTCIA3TestProtocol_16093pc5:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16093PC5 Indication\n");
      pkt_size = Cvcoctci2023_Construct16093Pc5Indication(&ind_params, outbuf, outbuf_size);
      break;
    case kTCIA3TestProtocol_80211:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI80211 Indication\n");
      pkt_size = Cvcoctci2023_Construct80211Indication(&ind_params, outbuf, outbuf_size);
      break;
    case kTCIA3TestProtocol_16094:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16094 Indication\n");
      pkt_size = Cvcoctci2023_Construct16094Indication(&ind_params, outbuf, outbuf_size);
      break;
    case kTCIA3TestProtocol_29451:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI29451 Indication\n");
      pkt_size = Cvcoctci2023_Construct29451Indication(&ind_params, outbuf, outbuf_size);
      break;
    case kTCIA3TestProtocol_31611:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI31611 Indication\n");
      pkt_size = Cvcoctci2023_Construct31611Indication(&ind_params, outbuf, outbuf_size);
      break;
    default:
      Err("Fail to construct Indication - invalid test protocol %d\n", g_tcia_mib.testing.test_protocol);
      pkt_size = -1;
  }
  if (pkt_size <= 0) {
    Err("Fail to construct Indication - ret: %d\n", pkt_size);
    return -1;
  }

  Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d bytes Indication\n", pkt_size);
  return pkt_size;
}


/**
 * @brief ICMPv6 패킷 수신 이벤트에 관련된 Indication 메시지를 생성한다.
 * @param[in] if_idx 패킷을 수신한 인터페이스 식별번호
 * @param[in] src_ipv6_addr 패킷 송신지의 IPv6 주소
 * @param[in] ip_pkt 수신된 IPv6 패킷
 * @param[in] ip_pkt_size 수신된 IPv6 패킷의 크기
 * @param[out] outbuf 생성된 Indication 메시지가 저장/반환될 버퍼
 * @param[in] outbuf_size outbuf 버퍼의 크기
 * @retval 양수: 생성된 Indication 메시지의 크기 (성공)
 * @retval -1: 실패
 */
int TCIA2023_ConstructIndication_ICMPv6PktRx(
  unsigned int if_idx,
  uint8_t *src_ipv6_addr,
  uint8_t *ip_pkt,
  size_t ip_pkt_size,
  uint8_t *outbuf,
  size_t outbuf_size)
{
  Log(kTCIA3LogLevel_DetailedEvent, "Construct Indication for rx ICMPv6 pkt\n");

  /*
   * Indication 메시지 생성을 위한 파라미터 정보를 채운다.
   */
  struct Cvcoctci2023Indication ind_params;
  memset(&ind_params, 0, sizeof(ind_params));
  ind_params.radio.radio = if_idx;
  ind_params.event = kCvcoctci2023Event_Icmp6PktRx;
  ind_params.event_params_type = kCvcoctci2023EventParamsType_Ip;
  ind_params.options.pdu = true;
  ind_params.pdu.pdu_type = kCvcoctci2023PduType_ipv6payload;
  ind_params.pdu.pdu_data = ip_pkt;
  ind_params.pdu.pdu_data_size = ip_pkt_size;
  ind_params.options.event_params = true;
  struct Cvcoctci2023IpParameters *ip_event_params = &(ind_params.event_params.ip);
  sprintf(ip_event_params->if_name, "wave%u", if_idx);
  memcpy(ip_event_params->src_ip_addr, src_ipv6_addr, IPv6_ALEN);
  ip_event_params->protocol = kCvcoctci2023Protocol_icmpv6;

  /*
   * Indication 메시지를 생성한다.
   */
  int ind_pkt_size;
  switch (g_tcia_mib.testing.test_protocol) {
    case kTCIA3TestProtocol_16093dsrc:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16093DSRC Indication\n");
      ind_pkt_size = Cvcoctci2023_Construct16093DsrcIndication(&ind_params, outbuf, outbuf_size);
      break;
    case kTCIA3TestProtocol_16093pc5:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16093PC5 Indication\n");
      ind_pkt_size = Cvcoctci2023_Construct16093Pc5Indication(&ind_params, outbuf, outbuf_size);
      break;
    case kTCIA3TestProtocol_16094:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16094 Indication\n");
      ind_pkt_size = Cvcoctci2023_Construct16094Indication(&ind_params, outbuf, outbuf_size);
      break;
    default:
      Err("Fail to construct Indication - invalid test protocol %d\n", g_tcia_mib.testing.test_protocol);
      ind_pkt_size = -1;
  }
  if (ind_pkt_size <= 0) {
    Err("Fail to construct Indication - ret: %d\n", ind_pkt_size);
    return -1;
  }

  Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d bytes Indication\n", ind_pkt_size);
  return ind_pkt_size;
}


/**
 * @brief UDP 패킷 수신 이벤트에 관련된 Indication 메시지를 생성한다.
 * @param[in] if_idx 패킷을 수신한 인터페이스 식별번호
 * @param[in] src_ipv6_addr 패킷 송신지의 IPv6 주소
 * @param[in] ip_payload 수신된 IPv6 페이로드
 * @param[in] ip_payload_size 수신된 IPv6 페이로드의 크기
 * @param[out] outbuf 생성된 Indication 메시지가 저장/반환될 버퍼
 * @param[in] outbuf_size outbuf 버퍼의 크기
 * @retval 양수: 생성된 Indication 메시지의 크기 (성공)
 * @retval -1: 실패
 */
int TCIA2023_ConstructIndication_UDPPktRx(
  unsigned int if_idx,
  uint8_t *src_ipv6_addr,
  uint8_t *ip_payload,
  size_t ip_payload_size,
  uint8_t *outbuf,
  size_t outbuf_size)
{
  Log(kTCIA3LogLevel_DetailedEvent, "Construct Indication for rx UDP pkt\n");

  /*
   * Indication 메시지 생성을 위한 파라미터 정보를 채운다.
   */
  struct Cvcoctci2023Indication ind_params;
  memset(&ind_params, 0, sizeof(ind_params));
  ind_params.radio.radio = if_idx;
  ind_params.event = kCvcoctci2023Event_IPv6PktRx;
  ind_params.event_params_type = kCvcoctci2023EventParamsType_Ip;
  ind_params.options.pdu = true;
  ind_params.pdu.pdu_type = kCvcoctci2023PduType_ipv6payload;
  ind_params.pdu.pdu_data = ip_payload;
  ind_params.pdu.pdu_data_size = ip_payload_size;
  ind_params.options.event_params = true;
  struct Cvcoctci2023IpParameters *ip_event_params = &(ind_params.event_params.ip);
  sprintf(ip_event_params->if_name, "wave%u", if_idx);
  memcpy(ip_event_params->src_ip_addr, src_ipv6_addr, IPv6_ALEN);
  ip_event_params->protocol = kCvcoctci2023Protocol_udp;

  /*
   * Indication 메시지를 생성한다.
   */
  int ind_pkt_size;
  switch (g_tcia_mib.testing.test_protocol) {
    case kTCIA3TestProtocol_16093dsrc:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16093DSRC Indication\n");
      ind_pkt_size = Cvcoctci2023_Construct16093DsrcIndication(&ind_params, outbuf, outbuf_size);
      break;
    case kTCIA3TestProtocol_16093pc5:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16093PC5 Indication\n");
      ind_pkt_size = Cvcoctci2023_Construct16093Pc5Indication(&ind_params, outbuf, outbuf_size);
      break;
    case kTCIA3TestProtocol_16094:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16094 Indication\n");
      ind_pkt_size = Cvcoctci2023_Construct16094Indication(&ind_params, outbuf, outbuf_size);
      break;
    default:
      Err("Fail to construct Indication - invalid test protocol %d\n", g_tcia_mib.testing.test_protocol);
      ind_pkt_size = -1;
  }
  if (ind_pkt_size <= 0) {
    Err("Fail to construct Indication - ret: %d\n", ind_pkt_size);
    return -1;
  }

  Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d bytes Indication\n", ind_pkt_size);
  return ind_pkt_size;
}
