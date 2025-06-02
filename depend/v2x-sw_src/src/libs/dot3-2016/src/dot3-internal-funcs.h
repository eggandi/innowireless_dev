/** 
 * @file
 * @brief dot3 라이브러리 내부에서 사용되는 함수들을 정의한 헤더 파일
 * @date 2020-07-13
 * @author gyun
 */


#ifndef V2X_SW_DOT3_INTERNAL_FUNCS_H
#define V2X_SW_DOT3_INTERNAL_FUNCS_H

// 시스템 헤더 파일
#include <string.h>

// 라이브러리 헤더 파일
#include "dot3-2016/dot3-types.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal-defines.h"


/**
 * @brief PSID가 유효한 값을 가지는지 확인한다.
 * @param[in] psid 유효성을 체크할 psid 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidPSID(Dot3PSID psid)
{
  return (psid <= kDot3PSID_Max);
}


/**
 * @brief WSA Type 값이 유효한 값을 가지는지 확인한다.
 * @param[in] type 유효성을 체크할 WSA type 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWSAType(Dot3WSAType type)
{
  return ((type >= kDot3WSAType_Min) && (type <= kDot3WSAType_Max));
}


/**
 * @brief Priority가 유효한 값을 가지는지 확인한다.
 * @param[in] priority 유효성을 체크할 priority 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidPriority(Dot3Priority priority)
{
  return (priority <= kDot3Priority_Max);
}


/**
 * @brief 채널번호가 유효한 값을 가지는지 확인한다.
 * @param[in] chan_num 유효성을 체크할 채널번호 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidChannelNumber(Dot3ChannelNumber chan_num)
{
  return (chan_num <= kDot3ChannelNumber_Max);
}


#if 0 // NOTE:: 국내에서는 Operating class로 어떤 값을 사용할지 정의되어 있지 않으므로, 유효성 검사를 생략한다.
/**
 * @brief Operating class가 유효한 값을 가지는지 확인한다.
 * @param[in] op_class 유효성을 체크할 operating class 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidOperatingClass(Dot3OperatingClass op_class)
{
  return ((op_class == kDot3OperatingClass_5G_10MHz) || (op_class == kDot3OperatingClass_5G_20MHz));
}
#endif


/**
 * @brief DataRate가 유효한 값을 가지는지 확인한다.
 * @param[in] datarate 유효성을 체크할 DataRate 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidDataRate(Dot3DataRate datarate)
{
  switch(datarate) {
    case kDot3DataRate_3Mbps:
    case kDot3DataRate_4p5Mbps:
    case kDot3DataRate_6Mbps:
    case kDot3DataRate_9Mbps:
    case kDot3DataRate_12Mbps:
    case kDot3DataRate_18Mbps:
    case kDot3DataRate_24Mbps:
    case kDot3DataRate_27Mbps:
    case kDot3DataRate_36Mbps:
    case kDot3DataRate_48Mbps:
    case kDot3DataRate_54Mbps: {
      return true;
    default:
      return false;
    }
  }
}


/**
 * @brief 파워가 유효한 값을 가지는지 확인한다.
 * @param[in] power 유효성을 체크할 파워 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidPower(Dot3Power power)
{
  return ((power >= kDot3Power_Min) && (power <= kDot3Power_Max));
}


/**
 * @brief ProviderChannelAccess 값이 유효한 값을 가지는지 확인한다.
 * @param[in] chan_access 유효성을 체크할 channel access 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidProviderChannelAccess(Dot3ProviderChannelAccess chan_access)
{
  return (chan_access <= kDot3ProviderChannelAccess_Max);
}


/**
 * @brief ProviderServiceContext의 길이가 유효한지 확인한다.
 * @param[in] psc_len 유효성을 체크할 길이 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidPSCLen(Dot3PSCLen psc_len)
{
  return (psc_len <= kDot3PSCLen_Max);
}


/**
 * @brief RPCI 값이 유효한지 확인한다.
 * @param[in] rcpi 유효성을 체크할 길이 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidRCPI(Dot3RCPI rcpi)
{
  return (rcpi <= kDot3RCPI_Max);
}


/**
 * @brief WsaCountThreshold 값이 유효한지 확인한다.
 * @param[in] threshold 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWSACountThreshold(Dot3WSACountThreshold threshold)
{
  return ((threshold >= kDot3WSACountThreshold_Min) && (threshold <= kDot3WSACountThreshold_Max));
}


/**
 * @brief WsaCountThresholdInterval 값이 유효한지 확인한다.
 * @param[in] interval 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWSACountThresholdInterval(Dot3WSACountThresholdInterval interval)
{
  return ((interval >= kDot3WSACountThresholdInterval_Min) && (interval <= kDot3WSACountThresholdInterval_Max));
}


/**
 * @brief WsaIdentifier 값이 유효한지 확인한다.
 * @param[in] wsa_id 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWSAIdentifier(Dot3WSAIdentifier wsa_id)
{
  return (wsa_id <= kDot3WSAIdentifier_Max);
}


/**
 * @brief WsaContentCount 값이 유효한지 확인한다.
 * @param[in] content_cnt 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWSAContentCount(Dot3WSAContentCount content_cnt)
{
  return (content_cnt <= kDot3WSAContentCount_Max);
}


/**
 * @brief WsaAdvertiserId의 길이가 유효한지 확인한다.
 * @param[in] len 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWSAAdvertiserIDLen(Dot3WSAAdvertiserIDLen len)
{
  return ((len >= kDot3WSAAdvertiserIDLen_Min) && (len <= kDot3WSAAdvertiserIDLen_Max));
}


/**
 * @brief WSA의 RepeatRate 값이 유효한지 확인한다.
 * @param[in] repeat_rate 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWSARepeatRate(Dot3WSARepeatRate repeat_rate)
{
  return (repeat_rate <= kDot3WSARepeatRate_Max);
}


/**
 * @brief Latitude 값이 유효한지 확인한다.
 * @param[in] lat 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidLatitude(Dot3Latitude lat)
{
  return ((lat >= kDot3Latitude_Min) && (lat <= kDot3Latitude_Max));
}


/**
 * @brief Longitude 값이 유효한지 확인한다.
 * @param[in] lon 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidLongitude(Dot3Longitude lon)
{
  return ((lon >= kDot3Longitude_Min) && (lon <= kDot3Longitude_Max));
}


/**
 * @brief Elevation 값이 유효한지 확인한다.
 * @param[in] elev 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidElevation(Dot3Elevation elev)
{
  return ((elev >= kDot3Elevation_Min) && (elev <= kDot3Elevation_Max));
}


/**
 * @brief IPv6 prefix length 값이 유효한지 확인한다.
 * @param[in] len 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidIPv6PrefixLen(Dot3IPv6PrefixLen len)
{
  return ((len >= kDot3IPv6PrefixLen_Min) && (len <= kDot3IPv6PrefixLen_Max));
}


/**
 * @brief WRA Router lifetime 값이 유효한지 확인한다.
 * @param[in] lifetime 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWRARouterLifetime(Dot3WRARouterLifetime lifetime)
{
  return ((lifetime >= kDot3WRARouterLifetime_Min) && (lifetime <= kDot3WRARouterLifetime_Max));
}


/**
 * @brief ACI(Access Category Index) 값이 유효한지 확인한다.
 * @param[in] aci 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidACI(Dot3ACI aci)
{
  return (aci <= kDot3ACI_Max);
}


/**
 * @brief AIFSN 값이 유효한지 확인한다.
 * @param[in] aifsn 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidAIFSN(Dot3AIFSN aifsn)
{
  return (aifsn <= kDot3AIFSN_Max);
}


/**
 * @brief ECW 값이 유효한지 확인한다.
 * @param[in] ecw 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidECW(Dot3ECW ecw)
{
  return (ecw <= kDot3ECW_Max);
}


/**
 * @brief 페이로드 길이 값이 유효한지 확인한다.
 * @param[in] size 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWSMPayloadSize(Dot3WSMPayloadSize size)
{
  return (size <= kDot3WSMPayloadSize_Max);
}


/**
 * @brief WSM 길이 값이 유효한지 확인한다.
 * @param[in] size 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWSMSize(Dot3WSMSize size)
{
  return ((size >= kDot3WSMSize_Min) && (size <= kDot3WSMSize_Max));
}


/**
 * @brief MPDU 길이 값이 유효한지 확인한다.
 * @param[in] size 유효성을 체크할 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidMPDUSize(Dot3MPDUSize size)
{
  return ((size >= kDot3MPDUSize_Min) && (size <= kDot3MPDUSize_Max));
}


/**
 * @brief UAS 관리 주기가 유효한지 확인한다.
 * @param[in] interval UAS 관리 주기
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidUASManagementInterval(Dot3UASManagementInterval interval)
{
  return ((interval >= kDot3UASManagementInterval_Min) && (interval <= kDot3UASManagementInterval_Max));
}


/**
 * @brief WSA Service Info 내 Channel Index 값이 유효한지 확인한다.
 * @param[in] idx Channel Index 값
 * @retval true: 유효함
 * @retval false: 유효하지 않음
 */
static inline bool dot3_IsValidWSIChannelIndex(Dot3WSAChannelIndex idx)
{
  return ((idx >= kDot3WSAChannelIndex_Min) && (idx <= kDot3WSAChannelIndex_Max));
}


/**
 * @brief 두 PSC 정보가 동일한지 비교한다.
 * @param[in] psc1 비교할 PSC
 * @param[in] psc2 비교할 PSC
 * @retval true: 동일함
 * @retval false: 동일하지 않음
 */
static inline bool dot3_ComparePSC(const struct Dot3PSC *psc1, const struct Dot3PSC *psc2)
{
  if (psc1->len != psc2->len) {
    return false;
  }
  if (memcmp(psc1->psc, psc2->psc, psc1->len) != 0) {
    return false;
  }
  return true;
}


/**
 * @brief 두 MAC 주소가 동일한지 비교한다.
 * @param[in] addr1 비교할 MAC 주소
 * @param[in] addr2 비교할 MAC 주소
 * @retval true: 동일함
 * @retval false: 동일하지 않음
 */
static inline bool dot3_CompareMACAddress(const Dot3MACAddress addr1, const Dot3MACAddress addr2)
{
  return (memcmp(addr1, addr2, MAC_ALEN) == 0);
}


/**
 * @brief 두 Advertiser ID 정보가 동일한지 비교한다.
 * @param[in] id1 비교할 advertiser ID
 * @param[in] id2 비교할 advertiser ID
 * @retval true: 동일함
 * @retval false: 동일하지 않음
 */
static inline bool dot3_CompareAdvertiserID(const struct Dot3WSAAdvertiserID *id1, const struct Dot3WSAAdvertiserID *id2)
{
  if (id1->len != id2->len) {
    return false;
  }
  if (memcmp(id1->id, id2->id, id1->len) != 0) {
    return false;
  }
  return true;
}


/*
 * 라이브러리 내부에서 사용되는 함수들
 */
// dot3.c
int INTERNAL dot3_InitDot3(Dot3LogLevel log_level);
void INTERNAL dot3_ReleaseDot3(void);
int INTERNAL dot3_CheckEDCAParameterSet(const struct Dot3EDCAParameterSet *set);

// dot3-wsr.c
void INTERNAL dot3_InitWSRTable(struct Dot3WSRTable *table);
void INTERNAL dot3_FlushWSRTable(struct Dot3WSRTable *table);
int INTERNAL dot3_AddWSR(struct Dot3WSRTable *table, Dot3PSID psid);
int INTERNAL dot3_DeleteWSR(struct Dot3WSRTable *table, Dot3PSID psid);
void INTERNAL dot3_DeleteAllWSRs(struct Dot3WSRTable *table);
Dot3WSRNum INTERNAL dot3_GetWSRNum(struct Dot3WSRTable *table);
struct Dot3WSRTableEntry INTERNAL * dot3_FindWSRWithPSID(struct Dot3WSRTable *table, Dot3PSID psid);

// dot3-psr.c
void INTERNAL dot3_InitPSRTable(struct Dot3PSRTable *table);
void INTERNAL dot3_FlushPSRTable(struct Dot3PSRTable *table);
int INTERNAL dot3_AddPSR(struct Dot3PSRTable *table, const struct Dot3PSR *psr);
int INTERNAL dot3_DeletePSR(struct Dot3PSRTable *table, Dot3PSID psid);
int INTERNAL dot3_ChangePSR(struct Dot3PSRTable *table, Dot3PSID psid, const char *psc);
void INTERNAL dot3_DeleteAllPSRs(struct Dot3PSRTable *table);
int INTERNAL dot3_GetPSRWithPSID(struct Dot3PSRTable *table, Dot3PSID psid, struct Dot3PSR *psr);
Dot3PSRNum INTERNAL dot3_GetPSRNum(struct Dot3PSRTable *table);

// dot3-usr.c
void INTERNAL dot3_InitUSRTable(struct Dot3USRTable *table);
void INTERNAL dot3_FlushUSRTable(struct Dot3USRTable *table);
struct Dot3USRTableEntry INTERNAL *dot3_FindMatchedUSR(
  struct Dot3USRTable *table,
  Dot3PSID psid,
  Dot3WSAType wsa_type,
  const Dot3MACAddress src_mac_addr,
  Dot3ChannelNumber chan_num,
  const struct Dot3PSC *psc,
  const struct Dot3WSAAdvertiserID *advertiser_id);
int INTERNAL dot3_AddUSR(struct Dot3USRTable *table, const struct Dot3USR *usr);
int INTERNAL dot3_DeleteUSR(struct Dot3USRTable *table, Dot3PSID psid);
void INTERNAL dot3_DeleteAllUSRs(struct Dot3USRTable *table);
int INTERNAL dot3_GetUSRWithPSID(struct Dot3USRTable *table, Dot3PSID psid, struct Dot3USR *usr);
Dot3USRNum INTERNAL dot3_GetUSRNum(struct Dot3USRTable *table);

// dot3-pci.c
int INTERNAL dot3_InitPCITable(struct Dot3PCITable *table);
void INTERNAL dot3_FlushPCITable(struct Dot3PCITable *table);
int INTERNAL dot3_AddOrUpdatePCI(struct Dot3PCITable *table, const struct Dot3PCI *pci);
int INTERNAL dot3_GetPCIWithChannel(struct Dot3PCITable *table, Dot3ChannelNumber chan_num, struct Dot3PCI *pci);
Dot3PCINum INTERNAL dot3_GetPCINum(struct Dot3PCITable *table);

// dot3-uas.c
int INTERNAL dot3_InitUASTable(struct Dot3UASTable *table);
void INTERNAL dot3_FlushUASTable(struct Dot3UASTable *table);
void INTERNAL dot3_DeleteAllUASs(struct Dot3UASTable *table);
struct Dot3UASSet INTERNAL * dot3_GetAllUASs(struct Dot3UASTable *table, int *err);
struct Dot3UASSet INTERNAL * dot3_GetUASsWithPSID(struct Dot3UASTable *table, Dot3PSID psid, int *err);
struct Dot3UASSet INTERNAL *
dot3_GetUASsWithSourceMACAddress(struct Dot3UASTable *table, const Dot3MACAddress addr, int *err);
struct Dot3UASSet INTERNAL *
dot3_GetUASsWithPSIDAndSourceMACAddress(struct Dot3UASTable *table, Dot3PSID psid, const Dot3MACAddress addr, int *err);
struct Dot3UASSet INTERNAL * dot3_GetUASsWithMaxRCPI(struct Dot3UASTable *table, int *err);
int INTERNAL dot3_AddOrUpdateUAS(
  struct Dot3UASTable *table,
  const uint8_t *wsa,
  size_t wsa_size,
  const Dot3MACAddress src_mac_addr,
  Dot3WSAType wsa_type,
  Dot3RCPI rcpi,
  Dot3Latitude tx_lat,
  Dot3Longitude tx_lon,
  Dot3Elevation tx_elev,
  const struct Dot3WSAHdr *hdr,
  const struct Dot3WSI *wsi,
  const struct Dot3WCI *wci,
  const struct Dot3WRA *wra);

// dot3-uas-mgmt.c
int INTERNAL dot3_StartUASManagementFunction(struct Dot3UASTable *table, Dot3UASManagementInterval interval);
void INTERNAL dot3_StopUASManagementFunction(struct Dot3UASTable *table);
int INTERNAL dot3_SetUASManagementTimerInterval(struct Dot3UASTable *table, unsigned int interval);

// dot3-wsa.c
uint8_t INTERNAL * dot3_ConstructWSA(const struct Dot3ConstructWSAParams *params, size_t *wsa_size, int *err);
int INTERNAL dot3_ParseWSA(const uint8_t *wsa, size_t encoded_wsa_size, struct Dot3ParseWSAParams *params);
int INTERNAL dot3_ProcessWSA(
  const uint8_t *wsa,
  size_t wsa_size,
  const Dot3MACAddress src_mac_addr,
  Dot3WSAType wsa_type,
  Dot3RCPI rcpi,
  Dot3Latitude tx_lat,
  Dot3Longitude tx_lon,
  Dot3Elevation tx_elev,
  struct Dot3ParseWSAParams *params);

// dot3-log.c
void INTERNAL dot3_PrintLog(const char *func, const char *format, ...);

// dot3-mpdu.c
uint8_t INTERNAL *
dot3_ConstructMPDU(struct Dot3MACProcessParams *params, uint8_t *msdu, size_t msdu_size, size_t *mpdu_size, int *err);
int INTERNAL dot3_ParseMPDU(const uint8_t *mpdu, struct Dot3MACProcessParams *params);

// dot3-wsm.c
uint8_t INTERNAL * dot3_ConstructWSM(
  struct Dot3WSMConstructParams *params,
  const uint8_t *payload,
  Dot3WSMPayloadSize payload_size,
  size_t *wsm_size,
  int *err);
uint8_t INTERNAL * dot3_ParseWSM(
  const uint8_t *wsm,
  Dot3WSMSize wsm_size,
  size_t *payload_size,
  struct Dot3WSMParseParams *params,
  int *ret);

#endif //V2X_SW_DOT3_INTERNAL_FUNCS_H
