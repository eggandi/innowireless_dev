/**
 * @file
 * @brief WSA 생성 및 파싱하는 기능을 구현한 파일
 * @date 2019-08-17
 * @author gyun
 */

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"
#if defined(_OBJASN1C_)
  #include "dot3-objasn1c.h"
#elif defined(_FFASN1C_)
  #include "dot3-ffasn1c.h"
#endif


/**
 * @brief WSA 를 생성한다.
 * @param[in] params WSA 헤더구성정보
 * @param[out] wsa_size 생성된 WSA의 길이가 반환될 변수의 포인터
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수의 포인터
 * @retval 생성된 WSA: 성공
 * @retval NULL: 실패
 *
 * 빌드 옵션(CMakeLists.txt 참조)에 따른 ASN.1 라이브러리가 적용된다.
 */
uint8_t INTERNAL * dot3_ConstructWSA(const struct Dot3ConstructWSAParams *params, size_t *wsa_size, int *err)
{
#if defined(_OBJASN1C_)
  return dot3_objasn1c_EncodeWSA(params, wsa_size, err);
#elif defined(_FFASN1C_)
  return dot3_ffasn1c_EncodeWSA(params, wsa_size, err);
#else
  #error "3rd party asn.1 library is not defined"
#endif
}


/**
 * @brief WSA를 파싱한다.
 * @param[in] wsa 파싱할 WSA가 담긴 버퍼 (UPER 인코딩 된 상태)
 * @param[in] wsa_size WSA의 길이
 * @param[out] params 파싱된 정보가 저장될 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 *
 * 빌드 옵션(CMakeLists.txt 참조)에 따른 ASN.1 라이브러리가 적용된다.
 */
int INTERNAL dot3_ParseWSA(const uint8_t *wsa, size_t wsa_size, struct Dot3ParseWSAParams *params)
{
#if defined(_OBJASN1C_)
  return dot3_objasn1c_DecodeWSA(wsa, wsa_size, params);
#elif defined(_FFASN1C_)
  return dot3_ffasn1c_DecodeWSA(wsa, wsa_size, params);
#else
  #error "3rd party asn.1 library is not defined"
#endif
}


/**
 * @brief WSA 헤더 정보가 유효한지 확인한다.
 * @param[in] hdr WSA 헤더 정보
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 *
 * WSA id, content count, repeat rate, latitude, longitude, elevation은 유효하지 않은 값은 인코딩 자체가 불가능하다.
 * 따라서 ASN.1으로 수신되는 데이터는 모두 유효한 값으로 본다.
 */
static int dot3_CheckWSAHdr(const struct Dot3WSAHdr *hdr)
{
  if (hdr->msg_id != kDot3SrvAdvMessageType_WSA) {
    return -kDot3Result_InvalidWSAMessage;
  }
  if (hdr->version != kDot3WSAVersion_Current) {
    return -kDot3Result_InvalidWSAVersion;
  }
  return kDot3Result_Success;
}


/**
 * @brief WSI(WSA Service Info) 정보가 유효한지 확인한다.
 * @param[in] wsi WSI 정보
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_CheckWSI(const struct Dot3WSI *wsi)
{
  if (dot3_IsValidPSID(wsi->psid) == false) {
    return -kDot3Result_InvalidPSID;
  }
  if (dot3_IsValidWSIChannelIndex(wsi->channel_index) == false) {
    return -kDot3Result_InvalidChannelIndex;
  }
  if ((wsi->extensions.rcpi_threshold == true) &&
      (dot3_IsValidRCPI(wsi->rcpi_threshold) == false)) {
    return -kDot3Result_InvalidWSARCPIThreshold;
  }
  if ((wsi->extensions.wsa_cnt_threshold == true) &&
      (dot3_IsValidWSACountThreshold(wsi->wsa_cnt_threshold) == false)) {
    return -kDot3Result_InvalidWSACountThreshold;
  }
  if ((wsi->extensions.wsa_cnt_threshold_interval == true) &&
      (dot3_IsValidWSACountThresholdInterval(wsi->wsa_cnt_threshold_interval) == false)) {
    return -kDot3Result_InvalidWSACountThresholdInterval;
  }
  return kDot3Result_Success;
}


/**
 * @brief WCI(WSA Channel Info) 정보가 유효한지 확인한다.
 * @param[in] wci WCI 정보
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 *
 * transmit_power_level은 유효하지 않은 값은 인코딩 자체가 불가능하다.
 * 따라서 ASN.1으로 수신되는 데이터는 모두 유효한 값으로 본다.
 */
static int dot3_CheckWCI(const struct Dot3WCI *wci)
{
#if 0 // NOTE:: 국내에서는 Operating class로 어떤 값을 사용할지 정의되어 있지 않으므로, 유효성 검사를 생략한다.
  if (dot3_IsValidOperatingClass(wci->operating_class) == false) {
    return -kDot3Result_InvalidOperatingClass;
  }
#endif
  if (dot3_IsValidChannelNumber(wci->chan_num) == false) {
    return -kDot3Result_InvalidChannelNumber;
  }
  if (dot3_IsValidDataRate(wci->datarate) == false) {
    return -kDot3Result_InvalidDataRate;
  }
  if ((wci->extension.chan_access == true) &&
      (wci->chan_access > kDot3ProviderChannelAccess_AlternatingTimeSlot0Only)) {
    return -kDot3Result_InvalidChannelAccess;
  }
  if (wci->extension.edca_param_set == true) {
    return dot3_CheckEDCAParameterSet(&(wci->edca_param_set));
  }
  return kDot3Result_Success;
}


/**
 * @brief WRA 정보가 유효한지 확인한다.
 * @param[in] wra WRA 정보
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_CheckWRA(const struct Dot3WRA *wra)
{
  if (dot3_IsValidWRARouterLifetime(wra->router_lifetime) == false) {
    return -kDot3Result_InvalidWRARouterLifetime;
  }
  if (dot3_IsValidIPv6PrefixLen(wra->ip_prefix_len) == false) {
    return -kDot3Result_InvalidIPv6PrefixLen;
  }
  return kDot3Result_Success;
}


/**
 * @brief WSA를 처리한다.
 * @param[in] wsa 처리할 WSA가 담긴 버퍼.
 * @param[in] wsa_size wsa 버퍼에 담긴 WSA의 길이
 * @param[in] src_mac_addr WSA 송신지 MAC 주소
 * @param[in] wsa_type WSA 유형
 * @param[in] rcpi WSA 수신 세기
 * @param[in] tx_lat WSA 송신지 위도
 * @param[in] tx_lon WSA 송신지 경도
 * @param[in] tx_elev WSA 송신지 고도
 * @param[in] params WSA 파싱 정보
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 *
 * WSA 정보를 이용하여 UAS가 생성되거나 업데이트된다.\n
 * WSA 헤더가 유효하지 않은 경우 실패를 리턴한다.\n
 * 하지만 WRA 및 Service Info, Channel Info가 유효하지 않은 경우에는 해당 UAS만 생성되지 않고 함수는 성공을 리턴한다.
 */
int INTERNAL dot3_ProcessWSA(
  const uint8_t *wsa,
  size_t wsa_size,
  const Dot3MACAddress src_mac_addr,
  Dot3WSAType wsa_type,
  Dot3RCPI rcpi,
  Dot3Latitude tx_lat,
  Dot3Longitude tx_lon,
  Dot3Elevation tx_elev,
  struct Dot3ParseWSAParams *params)
{
  Log(kDot3LogLevel_Event, "Process WSA\n");

  int ret;
  struct Dot3WSAHdr *hdr = &(params->hdr);
  ret = dot3_CheckWSAHdr(hdr);
  if (ret < 0) {
    Err("Fail to process WSA - invalid value in WSA header: %d\n", ret);
    return ret;
  }

  struct Dot3WSAAdvertiserID *advertiser_id = NULL;
  if (hdr->extensions.advertiser_id == true) {
    advertiser_id = &(hdr->advertiser_id);
  }

  struct Dot3WRA *wra = NULL;
  if (params->present.wra == true) {
    // WRA 정보가 유효한 경우에만 해당 정보를 사용한다(= UAS에 저장한다).
    ret = dot3_CheckWRA(&(params->wra));
    if (ret < 0) {
      Err("Invalid value in WRA: %d\n", ret);
    } else {
      wra = &(params->wra);
    }
  }

  /*
   * WSA 내 각 Service Info 별로 매칭되는 USR를 테이블에서 탐색하여;
   *  - 매칭되는 USR이 있는 경우 : UAS를 생성 또는 업데이트 한다.
   *  - 매칭되는 USR이 없는 경우 : 아무 동작도 하지 않는다.
   */
  struct Dot3WSI *wsi;
  struct Dot3WCI *wci;
  struct Dot3USRTableEntry *usr_entry;
  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  struct Dot3USRTable *usr_table = &(g_dot3_mib.user_info.usr_table);
  struct Dot3UASTable *uas_table = &(g_dot3_mib.user_info.uas_table);
  struct Dot3PSC *psc;
  Dot3ChannelNumber chan_num;
  unsigned int wci_idx;
  pthread_mutex_lock(&(uinfo->mtx));
  for (unsigned int i = 0; i < params->wsi_num; i++)
  {
    wsi = &(params->wsis[i]);
    ret = dot3_CheckWSI(wsi);
    if (ret < 0) {
      Err("Fail to process WSI[%u] - invalid value in WSI: %d\n", i, ret);
      continue;
    }

    wci_idx = wsi->channel_index - 1;

    // Service Info의 Channel index 값이 유효하지 않으면(실제 수납된 Channel Info에 매칭되지 않음), 스킵한다.
    if (wci_idx >= params->wci_num) {
      Err("Fail to process WSI[%u] - no channel info for channel_index(%u) in WSA\n", i, wsi->channel_index);
      continue;
    }

    wci = &(params->wcis[wci_idx]);
    ret = dot3_CheckWCI(wci);
    if (ret < 0) {
      Err("Fail to process WCI[%u] - invalid value in WCI: %d\n", wci_idx, ret);
      continue;
    }

    chan_num = wci->chan_num;
    if (wsi->extensions.psc == true) {
      psc = &(wsi->psc);
    } else {
      psc = NULL;
    }

    // 본 Service Info에 매칭되는 USR이 등록되어 있는지 탐색한다.
    // 매칭되는 USR이 등록되어 있지 않으면 UAS를 생성하지 않는다.
    // PSID, WSA type가 필수로 같아야 하며, 옵션으로 송신지 MAC 주소, 채널번호, PSC, Advertiser ID가 같아야 한다.
    usr_entry = dot3_FindMatchedUSR(usr_table, wsi->psid, wsa_type, src_mac_addr, chan_num, psc, advertiser_id);
    if (usr_entry == NULL) {
      Log(kDot3LogLevel_Event, "No USR for PSID(%u)\n", wsi->psid);
      continue;
    }

    // UAS를 추가하거나 업데이트한다.
    ret = dot3_AddOrUpdateUAS(uas_table,
                              wsa,
                              wsa_size,
                              src_mac_addr,
                              wsa_type,
                              rcpi,
                              tx_lat,
                              tx_lon,
                              tx_elev,
                              hdr,
                              wsi,
                              wci,
                              wra);
    if (ret < 0) {
      pthread_mutex_unlock(&(uinfo->mtx));
      return ret;
    }
  }
  pthread_mutex_unlock(&(uinfo->mtx));
  return kDot3Result_Success;
}
