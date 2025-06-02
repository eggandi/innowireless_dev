/**
 * @file
 * @brief WSA 관련 기능을 구현한 파일
 * @date 2019-09-27
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#if defined(_LTEV2X_HAL_)
#include "dot3-2016/dot3.h"
#else
#include "dot3/dot3.h"
#endif
#include "wlanaccess/wlanaccess.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief WSA를 생성한다.
 * @param[in] outbuf 생성된 WSA 가 저장될 버퍼
 * @param[in] outbuf_size outbuf 버퍼의 크기
 * @retval 양수: WSA의 길이(성공))
 * @retval -1: 실패
 */
int TCIA2023_ConstructWSA(uint8_t *outbuf)
{
  Log(kTCIA3LogLevel_DetailedEvent, "Construct WSA\n");

  struct TCIA3WSAInfo *wsa_info = &(g_tcia_mib.wsa_info);
  struct TCIA3WSAHdrInfo *wsa_hdr_info = &(wsa_info->hdr_info);
  struct TCIA3WRAInfo *wra_info = &(wsa_info->wra_info);
  struct Dot3ConstructWSAParams wsa_params;
  memset(&wsa_params, 0, sizeof(wsa_params));

  wsa_params.hdr.version = kDot3WSAVersion_Current;
  wsa_params.hdr.wsa_id = 0;
  wsa_params.hdr.content_count = ((wsa_hdr_info->content_count++) % 16);
  wsa_params.hdr.extensions.repeat_rate = wsa_hdr_info->options.repeat_rate;
  if (wsa_params.hdr.extensions.repeat_rate) {
    wsa_params.hdr.repeat_rate = wsa_hdr_info->repeat_rate;
  }
  wsa_params.hdr.extensions.twod_location = wsa_hdr_info->options.twod_location;
  if (wsa_params.hdr.extensions.twod_location) {
    wsa_params.hdr.twod_location.latitude = wsa_hdr_info->latitude;
    wsa_params.hdr.twod_location.longitude = wsa_hdr_info->longitude;
  }
  wsa_params.hdr.extensions.threed_location = wsa_hdr_info->options.threed_location;
  if (wsa_params.hdr.extensions.threed_location) {
    wsa_params.hdr.threed_location.latitude = wsa_hdr_info->latitude;
    wsa_params.hdr.threed_location.longitude = wsa_hdr_info->longitude;
    wsa_params.hdr.threed_location.elevation = wsa_hdr_info->elevation;
  }
  wsa_params.hdr.extensions.advertiser_id = wsa_hdr_info->options.advertiser_id;
  if (wsa_params.hdr.extensions.advertiser_id) {
    wsa_params.hdr.advertiser_id.len = wsa_hdr_info->advertiser_id.len;
    memcpy(wsa_params.hdr.advertiser_id.id, wsa_hdr_info->advertiser_id.id, wsa_params.hdr.advertiser_id.len);
  }
  wsa_params.present.wra = wra_info->options.wra;
  if (wsa_params.present.wra) {
    wsa_params.wra.router_lifetime = wra_info->router_lifetime;
    memcpy(wsa_params.wra.ip_prefix, wra_info->ip_prefix, IPv6_ALEN);
    wsa_params.wra.ip_prefix_len = wra_info->ip_prefix_len;
    memcpy(wsa_params.wra.default_gw, wra_info->default_gw, IPv6_ALEN);
    memcpy(wsa_params.wra.primary_dns, wra_info->primary_dns, IPv6_ALEN);
    wsa_params.wra.present.secondary_dns = wra_info->options.secondary_dns;
    if (wsa_params.wra.present.secondary_dns) {
      memcpy(wsa_params.wra.secondary_dns, wra_info->secondary_dns, IPv6_ALEN);
    }
    wsa_params.wra.present.gateway_mac_addr = wra_info->options.gw_mac_addr;
    if (wsa_params.wra.present.gateway_mac_addr) {
      memcpy(wsa_params.wra.gateway_mac_addr, wra_info->gw_mac_addr, MAC_ALEN);
    }
  }
  int ret;
  size_t wsa_size;
  uint8_t *wsa = Dot3_ConstructWSA(&wsa_params, &wsa_size, &ret);
  if (wsa == NULL) {
    Err("Fail to construct WSA - ret: %d\n", wsa_size);
    return -1;
  }
  memcpy(outbuf, wsa, wsa_size);
  free(wsa);
  Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d bytes WSA\n", wsa_size);
  return wsa_size;
}


/**
 * @brief WSA 송신타이머 만기 쓰레드. 송신타이머 만기 시마다 호출된다.
 * @param arg 사용되지 않음
 *
 * 송신타이머 컨디션 시그널을 전송하여 송신쓰레드가 깨어나도록 한다.
 */
static void TCIA2023_WSATxTimerThread(union sigval arg)
{
  (void)arg;
  struct TCIA3WSAInfo *wsa_info = &(g_tcia_mib.wsa_info);
  struct TCIA3WSATxInfo *wsa_tx_info = &(wsa_info->tx_info);
  struct TCIA3WSAHdrInfo *wsa_hdr_info = &(wsa_info->hdr_info);

  /*
   * 전송 상태가 아니면 종료한다.
   */
  if (wsa_tx_info->txing == false) {
    return;
  }

  /*
   * signer id type 결정한다.
   */
  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;
  memset(&params, 0, sizeof(params));

  if (wsa_info->sec_info.signer_id_type == kCvcoctci2023SignerIdentifierType_Unsecure) {
    params.type = kDot2SPDUConstructType_Unsecured;
  }
  else if (wsa_info->sec_info.signer_id_type == kCvcoctci2023SignerIdentifierType_UseSecProfilePerContentType) {
    params.type = kDot2SPDUConstructType_Signed;
    params.signed_data.signer_id_type = kDot2SignerId_Profile;
  }
  else if (wsa_info->sec_info.signer_id_type == kCvcoctci2023SignerIdentifierType_SignIncludeCertificate) {
    params.type = kDot2SPDUConstructType_Signed;
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
  }
  else if (wsa_info->sec_info.signer_id_type == kCvcoctci2023SignerIdentifierType_SignIncludeDigest) {
    params.type = kDot2SPDUConstructType_Signed;
    params.signed_data.signer_id_type = kDot2SignerId_Digest;
  }

  /*
   * Ieee1609Dot2Data 를 생성한다.
   */
  params.signed_data.psid = kDot3PSID_WSA;
  params.signed_data.gen_location.lat = wsa_hdr_info->latitude;
  params.signed_data.gen_location.lon = wsa_hdr_info->longitude;
  params.signed_data.gen_location.elev = wsa_hdr_info->elevation;
  res = Dot2_ConstructSPDU(&params, wsa_info->wsa, wsa_info->wsa_size);
  if (res.ret < 0) {
    Err("Fail to Dot2_ConstructSPDU(): %d\n", res.ret);
    return;
  }
  Log(kTCIA3LogLevel_DetailedEvent, "Success to Dot2_ConstructSPDU()\n");

#if defined(_TCIA2023_DSRC_)
  TCIA2023_DSRC_TransmitWSA(res.spdu, (size_t)res.ret);
#elif defined(_TCIA2023_LTE_V2X_)
  TCIA2023_LTE_V2X_TransmitWSA(res.spdu, (size_t)res.ret);
#else
#error "Communication type is not defined"
#endif
  free(res.spdu);
}


/**
 * @brief WSA 송신타이머를 초기화한다.
 * @param[in] interval 송신주기(msec 단위)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_InitWSATxTimer(unsigned int interval)
{
  int ret;
  struct itimerspec ts;
  struct sigevent se;

  Log(kTCIA3LogLevel_Event, "Initialize WSA tx timer - interval: %u msec\n", interval);

  /*
   * 송신타이머 만기 시 송신타이머쓰레드(TCIA2023_TxTimerThread)가 생성되도록 설정한다.
   */
  se.sigev_notify = SIGEV_THREAD;
  se.sigev_value.sival_ptr = NULL;
  se.sigev_notify_function = TCIA2023_WSATxTimerThread;
  se.sigev_notify_attributes = NULL;

  ts.it_value.tv_sec = 0;
  ts.it_value.tv_nsec = 100000;  // 최초타이머 주기 = 100usec
  ts.it_interval.tv_sec = interval / 1000;
  ts.it_interval.tv_nsec = (interval % 1000) * 1000000;

  /*
   * 송신타이머 생성
   */
  ret = timer_create(CLOCK_MONOTONIC, &se, &(g_tcia_mib.wsa_info.tx_info.tx_timer));
  if (ret) {
    Err("Fail to create timer: %m\n");
    return -1;
  }

  /*
   * 송신타이머 주기 설정
   */
  ret = timer_settime(g_tcia_mib.wsa_info.tx_info.tx_timer, 0, &ts, 0);
  if (ret) {
    Err("Fail to set timer: %m\n");
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to initialize tx timer.\n");
  return 0;
}


/**
 * @brief WSA 전송을 시작한다.
 * @retval 0: 성공
 * @retval -1: 실패
 *
 *  WSA 전송 쓰레드와 타이머를 생성하여 주기적으로 전송한다.
 */
int TCIA2023_StartWSATransmit(void)
{
  int ret;
  Log(kTCIA3LogLevel_Event, "Start WSA transmit\n");

  struct TCIA3WSAInfo *wsa_info = &(g_tcia_mib.wsa_info);
  struct TCIA3WSATxInfo *wsa_tx_info = &(g_tcia_mib.wsa_info.tx_info);
#if defined(_LTEV2X_HAL_)
  struct TCIA3FlowInfo *flow_info = &(g_tcia_mib.flow_info[wsa_tx_info->flow_id]);
#endif

  /*
   * 전송 주기 계산
   */
  unsigned int tx_interval_msec;
  if (wsa_tx_info->repeat_rate > 0) {
    tx_interval_msec = 5000 / wsa_tx_info->repeat_rate;
#if defined(_TCIA2023_LTE_V2X_)
#if defined(_LTEV2X_HAL_)
    if (tx_interval_msec > flow_info->interval && flow_info->interval != kLTEV2XHALTxFLowInterval_None) {
      tx_interval_msec = flow_info->interval;
    }
#endif
#endif
  } else {
    tx_interval_msec = 100U; // 기본값
  }

#if defined(_TCIA2023_LTE_V2X_)
#if defined(_LTEV2X_HAL_)
  if (flow_info->size == kLTEV2XHALMSDUSize_None) {
    flow_info->size = wsa_info->wsa_size;
  }
  if (flow_info->type == kLTEV2XHALTxFlowType_SPS) {
    ret = TCIA2023_LTE_V2X_RegisterTransmitFlow(flow_info->index, flow_info->pppp, flow_info->interval, 0);
    if (ret < 0) {
      return -1;
    }
  }
#else
  /*
   * 송신 플로우를 등록한다.
   */
  ret = TCIA2023_LTE_V2X_RegisterTransmitFlow(kDot3PSID_WSA, wsa_tx_info->tx_power, wsa_tx_info->priority, tx_interval_msec);
  if (ret < 0) {
    return -1;
  }
#endif
#endif

  /*
   * 송신 타이머 생성
   */
  ret = TCIA2023_InitWSATxTimer(tx_interval_msec);
  if (ret < 0) {
    return -1;
  }

  /*
   * 송신 중임을 표시한다.
   */
  wsa_tx_info->txing = true;

  Log(kTCIA3LogLevel_Event, "Success to start WSA transmit\n");\
  return 0;
}


/**
 * @brief WSA 전송을 종료한다.
 *
 * WSA 전송 쓰레드와 타이머를 종료한다.
 */
void TCIA2023_StopWSATransmit(void)
{
  Log(kTCIA3LogLevel_Event, "Stop WSA transmit\n");

  /*
   * 전송 중이면 전송 동작을 중지한다.
   *  - 전송 쓰레드, 타이머 등을 제거한다.
   *  - 전송 큐를 비운다.
   */
  struct TCIA3WSAInfo *wsa_info = &(g_tcia_mib.wsa_info);
  struct TCIA3WSATxInfo *wsa_tx_info = &(g_tcia_mib.wsa_info.tx_info);
  if (wsa_tx_info->txing == true) {
    wsa_tx_info->txing = false;
    Log(kTCIA3LogLevel_Event, "Destroy tx timer\n");
    timer_delete(wsa_tx_info->tx_timer);
    usleep(500000);
    Log(kTCIA3LogLevel_Event, "Flush transmit queues\n");
#if defined(_TCIA_DSRC_)
    WAL_FlushTransmitQueue(wsa_tx_info->if_idx, kWalTimeSlot_0, 5);
    WAL_FlushTransmitQueue(wsa_tx_info->if_idx, kWalTimeSlot_1, 5);
#endif
    wsa_info->wsa_size = 0;
  }

  Log(kTCIA3LogLevel_Event, "Success to stop WSA transmit\n");
}


/**
 * @brief UAS 정보를 이용하여 채널에 접속한다.
 * @param[in] 채널에 접속할 인터페이스 식별번호
 * @param[in] uas UAS 정보
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_AccessChannelWithUASInfo(unsigned int if_idx, const struct Dot3UAS *uas)
{
#if defined(_TCIA2023_DSRC_)
  /*
   * UAS의 채널번호 및 채널접속유형에 따라 각 TimeSlot에서 접속할 채널을 결정한다.
   */
  Dot3ProviderChannelAccess chan_access;
  if (uas->present.chan_access) {
    chan_access = uas->chan_access;
  } else {
    chan_access = kDot3ProviderChannelAccess_AlternatingTimeSlot1Only;
  }
  WalChannelNumber ts0_chan_num = kWalChannelNumber_CCH, ts1_chan_num = kWalChannelNumber_CCH;
  if (chan_access == kDot3ProviderChannelAccess_AlternatingTimeSlot1Only) {
    ts0_chan_num = uas->chan_num;
  } else if (chan_access == kDot3ProviderChannelAccess_AlternatingTimeSlot0Only) {
    ts1_chan_num = uas->chan_num;
  } else {
    ts0_chan_num = uas->chan_num;
    ts1_chan_num = uas->chan_num;
  }

  /*
   * 채널에 접속한다.
   */
  int ret = TCIA2023_DSRC_AccessChannel(if_idx, ts0_chan_num, ts1_chan_num);
  if (ret < 0) {
    return -1;
  }
  Log(kWalLogLevel_Event, "Success to access channel with UAS info\n");
#elif defined(_TCIA2023_LTE_V2X_)
  (void)if_idx;
  (void)uas;
#endif

  return 0;
}


/**
 * @brief WSA 내용을 출력한다.
 * @param[in] params WSA 파싱 정보
 */
static void TCIA2023_PrintWSA(struct Dot3ParseWSAParams *params)
{
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Log(kTCIA3LogLevel_Event, "WSA contents\n");
    for (unsigned int cnt = 0; cnt < params->wsi_num; cnt++) {
      struct Dot3WSI *wsi = &(params->wsis[cnt]);
      Log(kTCIA3LogLevel_Event, "  WSI[%u] PSID: %u, ChannelIndex: %u\n", cnt, wsi->psid, wsi->channel_index);
      if (wsi->extensions.psc == true) {
        Log(kTCIA3LogLevel_Event, "          PSC: %s\n", wsi->psc.psc);
      }
      if (wsi->extensions.ipv6_address == true) {
        char addr_str[IPv6_ADDR_STR_MAX_LEN + 1];
        inet_ntop(AF_INET6, wsi->ipv6_address, addr_str, sizeof(addr_str));
        Log(kTCIA3LogLevel_Event, "          IPv6 address: %s\n", addr_str);
      }
      if (wsi->extensions.service_port == true) {
        Log(kTCIA3LogLevel_Event, "          Service port: %u\n", wsi->service_port);
      }
      if (wsi->extensions.provider_mac_address == true) {
        Log(kTCIA3LogLevel_Event, "          Provider MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
            wsi->provider_mac_address[0], wsi->provider_mac_address[1], wsi->provider_mac_address[2],
            wsi->provider_mac_address[3], wsi->provider_mac_address[4], wsi->provider_mac_address[5]);
      }
      if (wsi->extensions.rcpi_threshold == true) {
        Log(kTCIA3LogLevel_Event, "          RCPI threshold: %d\n", wsi->rcpi_threshold);
      }
      if (wsi->extensions.wsa_cnt_threshold == true) {
        Log(kTCIA3LogLevel_Event, "          WSA count threshold: %u\n", wsi->wsa_cnt_threshold);
      }
      if (wsi->extensions.wsa_cnt_threshold_interval == true) {
        Log(kTCIA3LogLevel_Event, "          WSA count threshold: %u\n", wsi->wsa_cnt_threshold_interval);
      }
    }
    for (unsigned int cnt = 0; cnt < params->wci_num; cnt++) {
      struct Dot3WCI *wci = &(params->wcis[cnt]);
      Log(kTCIA3LogLevel_Event,
          "  WCI[%u] op_class: %u, chan: %u, txpower: %ddBm, datarate: %u*500kbps, adaptable: %u\n",
          cnt,
          wci->operating_class,
          wci->chan_num,
          wci->transmit_power_level,
          wci->datarate,
          wci->adaptable_datarate);
      if (wci->extension.chan_access) {
        Log(kTCIA3LogLevel_Event, "          chan_access: %u(0:cont, 1:ts1, 2:ts0)\n", wci->chan_access);
      }
      if (wci->extension.edca_param_set) {
        Log(kTCIA3LogLevel_Event, "          EDCA parameter set: skip to print\n");
      }
    }
    if (params->present.wra == true) {
      struct Dot3WRA *wra = &(params->wra);
      Log(kTCIA3LogLevel_Event, "  WRA - lifetime: %u, prefix len: %u\n", wra->router_lifetime, wra->ip_prefix_len);
      char addr_str[IPv6_ADDR_STR_MAX_LEN + 1];
      inet_ntop(AF_INET6, wra->ip_prefix, addr_str, sizeof(addr_str));
      Log(kTCIA3LogLevel_Event, "          IP prefix: %s\n", addr_str);
      inet_ntop(AF_INET6, wra->default_gw, addr_str, sizeof(addr_str));
      Log(kTCIA3LogLevel_Event, "          default gateway: %s\n", addr_str);
      inet_ntop(AF_INET6, wra->primary_dns, addr_str, sizeof(addr_str));
      Log(kTCIA3LogLevel_Event, "          primary DNS: %s\n", addr_str);
      if (wra->present.secondary_dns == true) {
        inet_ntop(AF_INET6, wra->secondary_dns, addr_str, sizeof(addr_str));
        Log(kTCIA3LogLevel_Event, "          secondary DNS: %s\n", addr_str);
      }
      if (wra->present.gateway_mac_addr == true) {
        Log(kTCIA3LogLevel_Event, "          Gateway MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
            wra->gateway_mac_addr[0], wra->gateway_mac_addr[1], wra->gateway_mac_addr[2],
            wra->gateway_mac_addr[3], wra->gateway_mac_addr[4], wra->gateway_mac_addr[5]);
      }
    }
  }
}


/**
 * @brief IP 통신을 위한 Tx profile을 등록한다.
 * @param[in] if_idx Tx Profile을 등록할 인터페이스 식별번호
 * @param[in] chan_num 채널 번호
 * @param[in] power 송신 파워
 * @param[in] datarate 송신 데이터레이트
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_RegisterTxProfile(unsigned int if_idx, WalChannelNumber chan_num, WalPower power, WalDataRate datarate)
{
#if defined(_TCIA2023_DSRC_)
  struct WalTxProfile profile;
  profile.chan_num = chan_num;
  profile.power = power;
  profile.datarate = datarate;
  profile.priority = 0;

  int ret = WAL_RegisterTxProfile(if_idx, &profile);
  if (ret < 0) {
    Err("Fail to register tx profile - WAL_RegisterTxProfile() failed: %d\n", ret);
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to register tx profile - if_idx: %u, chan: %u, power: %d, datarate: %u, prio: %u\n",
      if_idx, profile.chan_num, profile.power, profile.datarate, profile.priority);
#elif defined(_TCIA2023_LTE_V2X_)
  (void)if_idx;
  (void)chan_num;
  (void)power;
  (void)datarate;
#endif
  return 0;
}


/**
 * @brief 수신된 WSA를 처리한다.
 * @param[in] if_idx WSA가 수신된 인터페이스 식별번호
 * @param[in] wsa 처리할 WSA가 담긴 버퍼
 * @param[in] wsa_size wsa 버퍼에 담긴 WSA의 길이
 * @param[in] src_mac_addr WSA 송신지 MAC 주소
 * @param[in] wsa_type WSA 유형
 * @param[in] rcpi WSA 수신 세기
 * @param[in] tx_lat WSA 송신지 위도
 * @param[in] tx_lon WSA 송신지 경도
 * @param[in] tx_elev WSA 송신지 고도
 * @param[out] params 파싱된 정보가 저장될 정보구조체의 포인터
 * @retval 0: 성공
 * @retval -1: 실패
 *
 * WSA 처리 후 UAS 정보를 확인하여, \n
 *  - IP Routing 서비스 정보가 포함되어 있는 경우 해당 채널에 접속하고 WRA 정보를 적용하고 Tx Profile을 등록한다.\n
 *  - 그 외의 서비스 정보는 무시한다
 *    (현 시점(2020.08)의 표준적합성 시험 기준으로, 그 외의 서비스에 대해서는 UAS를 기반으로 채널접속할 필요가 없다).
 */
int TCIA2023_ProcessRxWSA(
  unsigned int if_idx,
  const uint8_t *wsa,
  size_t wsa_size,
  Dot3MACAddress src_mac_addr,
  Dot3WSAType wsa_type,
  Dot3RCPI rcpi,
  Dot3Latitude tx_lat,
  Dot3Longitude tx_lon,
  Dot3Elevation tx_elev,
  struct Dot3ParseWSAParams *params)
{
  Log(kTCIA3LogLevel_Event, "Process %u-bytes rx WSA - if_idx: %u, RCPI: %d\n", wsa_size, if_idx, rcpi);

  /*
   * WSA를 처리한다.
   */
  int ret = Dot3_ProcessWSA(wsa, wsa_size, src_mac_addr, wsa_type, rcpi, tx_lat, tx_lon, tx_elev, params);
  if (ret < 0) {
    Err("Fail to process rx WSA - Dot3_ProcessWSA() failed: %d\n", ret);
    return -1;
  }
  TCIA2023_PrintWSA(params);

  /*
   * 첫번째 UAS 정보를 확인하여 IP routing 서비스일 경우 채널에 접속하고 WRA 정보를 적용하고 Tx Profile을 등록한다.
   */
  struct Dot3UASSet *set = Dot3_GetAllUASs(&ret);
  if (set == NULL) {
    Err("Fail to process rx WSA - Dot3_GetAllUASs() failed: %d\n", ret);
    return -1;
  }
  if (set->num == 0) {
    Err("Fail to process rx WSA - no UAS\n");
    return -1;
  }
  struct Dot3UAS *uas = set->uas;
  // Spirent TS가 RCPI threshold와 WSA count threshold를 포함한 WSA를 송신하는 경우가 있어, available하지 않을 수 있다.
  // (예: TC_16093_WSA_PP_BV_02 시험에서 RCPI threshold가 200인데,
  //  안테나 환경에서 시험 시 실제 수신 RCPI가 158로 측정되어 available할 수가 없다)
  // 따라서 아래 코드는 실행하지 않도록 한다.
#if 0
  if (uas->available == false) {
    Err("Fail to process rx WSA - UAS for PSID(%u) is not available\n", uas->psid);
    return -1;
  }
#endif

  if ((uas->psid == kDot3PSID_IPv6Routing) && (uas->present.wra == true)) {
    if (g_tcia_mib.ip_net_info.ip_service_running == true) {
      Log(kTCIA3LogLevel_Event, "IP service is already running\n");
      return 0;
    }
    if (TCIA2023_AccessChannelWithUASInfo(if_idx, uas) < 0) {
      return -1;
    }
    if (TCIA2023_ProcessRxWRA(if_idx, &(uas->wra)) < 0) {
      return -1;
    }
    if (TCIA2023_RegisterTxProfile(if_idx, uas->chan_num, uas->transmit_power_level, uas->datarate) < 0) {
      return -1;
    }
    g_tcia_mib.ip_net_info.ip_service_running = true;
  }

  Log(kTCIA3LogLevel_Event, "Success to process rx WSA\n");
  return 0;
}
