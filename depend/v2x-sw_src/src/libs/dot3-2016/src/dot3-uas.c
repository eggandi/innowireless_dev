/**
 * @file
 * @brief UAS(User Available Service) 관련 기능 구현 파일
 * @date 2020-07-25
 * @author gyun
 */


// 시스템 헤더 파일
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"
#include "dot3-mib.h"


/**
 * @brief UAS 테이블을 초기화한다.
 * @param[in] table UAS 테이블
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_InitUASTable(struct Dot3UASTable *table)
{
  Log(kDot3LogLevel_Init, "Initialize UAS table\n");
  memset(table, 0, sizeof(struct Dot3UASTable));
  TAILQ_INIT(&(table->head));
  return kDot3Result_Success;
}


/**
 * @brief UAS 테이블을 비운다.
 * @param[in] table UAS 테이블
 */
void INTERNAL dot3_FlushUASTable(struct Dot3UASTable *table)
{
  Log(kDot3LogLevel_Event, "Flush UAS table\n");
  dot3_DeleteAllUASs(table);
}


/**
 * @brief UAS 테이블에서 특정 송신지 MAC주소, WSA ID, PSID를 갖는 UAS 엔트리를 찾아 반환한다.
 * @param[in] table UAS 테이블
 * @param[in] src_mac_addr 찾고자 하는 UAS의 송신지 MAC 주소
 * @param[in] wsa_id 찾고자 하는 UAS의 WSA ID
 * @param[in] psid 찾고자 하는 UAS의 PSID
 * @retval NULL: 실패
 * @return UAS 엔트리 포인터
 */
static struct Dot3UASTableEntry *dot3_FindMatchedUAS(
  struct Dot3UASTable *table,
  const Dot3MACAddress src_mac_addr,
  Dot3WSAIdentifier wsa_id,
  Dot3PSID psid)
{
  struct Dot3UASTableEntry *entry;
  struct Dot3UAS *uas;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    uas = &(entry->uas);
    if ((uas->wsa_id == wsa_id) &&
        (uas->psid == psid) &&
        (dot3_CompareMACAddress(uas->src_mac_addr, src_mac_addr) == true)) {
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief 수신된 WSA 정보로부터 UAS 정보를 구성한다.
 * @param[in] src_mac_addr WSA 송신지 MAC 주소
 * @param[in] wsa_type WSA type
 * @param[in] rcpi WSA 수신 세기
 * @param[in] tx_lat 송신자 위도. 값이 없을 경우 Unavailable을 전달한다.
 * @param[in] tx_lon 송신자 경도. 값이 없을 경우 Unavailable을 전달한다.
 * @param[in] tx_elev 송신자 고도. 값이 없을 경우 Unavailable을 전달한다.
 * @param[in] hdr 수신된 WSA 헤더
 * @param[in] wsi 수신된 WSA 내 Sevice Info
 * @param[in] wci 수신된 WSA 내 Channel Info
 * @param[in] wra 수신된 WSA 내 WRA (없을 경우 NULL)
 * @param[out] uas 정보를 채울 UAS 정보 구조체
 */
static void dot3_ConstructUAS(
  const Dot3MACAddress src_mac_addr,
  Dot3WSAType wsa_type,
  Dot3RCPI rcpi,
  Dot3Latitude tx_lat,
  Dot3Longitude tx_lon,
  Dot3Elevation tx_elev,
  const struct Dot3WSAHdr *hdr,
  const struct Dot3WSI *wsi,
  const struct Dot3WCI *wci,
  const struct Dot3WRA *wra,
  struct Dot3UAS *uas)
{
  Log(kDot3LogLevel_Event, "Construct UAS\n");

  memset(uas, 0, sizeof(struct Dot3UAS));
  memcpy(uas->src_mac_addr, src_mac_addr, MAC_ALEN);
  uas->wsa_type = wsa_type;
  uas->rcpi = rcpi;
  uas->wsa_id = hdr->wsa_id;
  uas->psid = wsi->psid;
  uas->operating_class = wci->operating_class;
  uas->chan_num = wci->chan_num;
  uas->transmit_power_level = wci->transmit_power_level;
  uas->datarate = wci->datarate;
  uas->adaptable_datarate = wci->adaptable_datarate;
  if (hdr->extensions.advertiser_id == true) {
    uas->present.advertiser_id = true;
    memcpy(&(uas->advertiser_id), &(hdr->advertiser_id), sizeof(struct Dot3WSAAdvertiserID));
  }
  if (wsi->extensions.psc == true) {
    uas->present.psc = true;
    memcpy(&(uas->psc), &(wsi->psc), sizeof(struct Dot3PSC));
  }
  if (wsi->extensions.ipv6_address == true) {
    uas->present.ipv6_address = true;
    memcpy(uas->ipv6_address, wsi->ipv6_address, IPv6_ALEN);
  }
  if (wsi->extensions.service_port == true) {
    uas->present.service_port = true;
    uas->service_port = wsi->service_port;
  }
  if (wsi->extensions.provider_mac_address == true) {
    uas->present.provider_mac_address = true;
    memcpy(uas->provider_mac_address, wsi->provider_mac_address, MAC_ALEN);
  }
  if (wsi->extensions.rcpi_threshold == true) {
    uas->present.rcpi_threshold = true;
    uas->rcpi_threshold = wsi->rcpi_threshold;
  }
  if (wsi->extensions.wsa_cnt_threshold == true) {
    uas->present.wsa_cnt_threshold = true;
    uas->wsa_cnt_threshold = wsi->wsa_cnt_threshold;
  }
  if (wsi->extensions.wsa_cnt_threshold_interval == true) {
    uas->present.wsa_cnt_threshold_interval = true;
    uas->wsa_cnt_threshold_interval = wsi->wsa_cnt_threshold_interval;
  }
  if (wci->extension.chan_access == true) {
    uas->present.chan_access = true;
    uas->chan_access = wci->chan_access;
  }
  if (wci->extension.edca_param_set == true) {
    uas->present.edca_param_set = true;
    memcpy(&(uas->edca_param_set), &(wci->edca_param_set), sizeof(struct Dot3EDCAParameterSet));
  }
  if (wra) {
    uas->present.wra = true;
    memcpy(&(uas->wra), wra, sizeof(struct Dot3WRA));
  }

  // Tx latitude
  if (tx_lat != kDot3Latitude_Unavailable) {
    uas->tx_lat = tx_lat;
  } else {
    if(hdr->extensions.twod_location == true) {
      uas->tx_lat = hdr->twod_location.latitude;
    } else if (hdr->extensions.threed_location == true) {
      uas->tx_lat = hdr->threed_location.latitude;
    } else {
      uas->tx_lat = kDot3Latitude_Unavailable;
    }
  }
  // Tx longitude
  if (tx_lon != kDot3Longitude_Unavailable) {
    uas->tx_lon = tx_lon;
  } else {
    if (hdr->extensions.twod_location == true) {
      uas->tx_lon = hdr->twod_location.longitude;
    } else if (hdr->extensions.threed_location == true) {
      uas->tx_lon = hdr->threed_location.longitude;
    } else {
      uas->tx_lon = kDot3Longitude_Unavailable;
    }
  }
  // Tx elevation
  if (tx_elev != kDot3Elevation_Unavailable) {
    uas->tx_elev = tx_elev;
  } else {
    if (hdr->extensions.threed_location == true) {
      uas->tx_elev = hdr->threed_location.elevation;
    } else {
      uas->tx_elev = kDot3Elevation_Unavailable;
    }
  }
}


/**
 * @brief 수신 WSA로부터 생성/업데이트된 UAS의 유효성을 업데이트한다.
 * @param[in] rcpi WSA 수신 세기
 * @param[out] entry 업데이트할 UAS
 */
static inline void dot3_UpdateUASAvailableUsingRxWSA(Dot3RCPI rcpi, struct Dot3UASTableEntry *entry)
{
  struct Dot3UAS *uas = &(entry->uas);

  /*
   * 유효성을 판단하기 위해 WSA 수신카운트를 사용하는 경우, 유효성 판단을 보류한다.
   * 이 경우 유효성 판단은 관리쓰레드에서 주기적으로 수행된다.
   */
  if (entry->check_rx_cnt == true) {
    return;
  }

  /*
   * 유효성을 판단하기 위해 RCPI 기준값을 사용하지 않으면, 유효한 것으로 설정한다.
   */
  if (uas->present.rcpi_threshold == false) {
    Log(kDot3LogLevel_Event, "UAS status -> available (no rcpi and rx count threshold)\n");
    uas->available = true;
    return;
  }

  /*
   * 유효성을 판단하기 위해 RCPI 기준값이 사용되는 경우, 수신세기와 기준값을 비교하여 유효 여부를 판단한다.
   */
  else {
    if (rcpi >= uas->rcpi_threshold) {
      Log(kDot3LogLevel_Event, "UAS status -> available (high rcpi and no rx count threshold)\n");
      uas->available = true;
    } else {
      Log(kDot3LogLevel_Event, "UAS status -> unavailable (low rcpi and no rx count threshold)\n");
      uas->available = false;
    }
  }
}


/**
 * @brief 새로운 UAS 엔트리를 테이블에 추가한다.
 * @param[in] table UAS 테이블
 * @param[in] wsa 수신된 WSA 패킷데이터
 * @param[in] wsa_size 수신된 WSA 패킷데이터의 길이
 * @param[in] src_mac_addr WSA 송신지 MAC 주소
 * @param[in] wsa_type WSA 유형
 * @param[in] rcpi WSA 수신 세기
 * @param[in] tx_lat 송신자 위도. 값이 없을 경우 Unavailable을 전달한다.
 * @param[in] tx_lon 송신자 경도. 값이 없을 경우 Unavailable을 전달한다.
 * @param[in] tx_elev 송신자 고도. 값이 없을 경우 Unavailable을 전달한다.
 * @param[in] hdr 수신된 WSA 내 헤더 정보
 * @param[in] wsi 수신된 WSA 내 Service Info
 * @param[in] wci 수신된 WSA 내 Channel Info
 * @param[in] wra 수신된 WSA 내 WRA (없을 경우 NULL)
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_AddUASEntry(
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
  const struct Dot3WRA *wra)
{
  Log(kDot3LogLevel_Event, "Add UAS entry\n");

  /*
   * 테이블 오버플로우를 확인한다.
   */
  if (table->num >= kDot3UASNum_Max) {
    Err("Fail to add UAS entry - table is full (%u)\n", table->num);
    return -kDot3Result_UASTableFull;
  }

  /*
   * UAS 엔트리 메모리를 할당하고 정보를 저장한다.
   */
  struct Dot3UASTableEntry *entry = (struct Dot3UASTableEntry *)calloc(1, sizeof(struct Dot3UASTableEntry));
  if (entry == NULL) {
    return -kDot3Result_NoMemory;
  }
  dot3_ConstructUAS(src_mac_addr, wsa_type, rcpi, tx_lat, tx_lon, tx_elev, hdr, wsi, wci, wra, &(entry->uas));
  entry->wsa = (uint8_t *)calloc(1, wsa_size);
  if (entry->wsa == NULL) {
    free(entry);
    return -kDot3Result_NoMemory;
  }
  memcpy(entry->wsa, wsa, wsa_size);
  entry->wsa_size = wsa_size;
  if ((wsi->extensions.wsa_cnt_threshold == true) &&
      (wsi->extensions.wsa_cnt_threshold_interval == true)) {
    entry->check_rx_cnt = true;
    entry->rx_cnt_in_mgmt_timer_interval++;
  }
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  entry->expiry = ts.tv_sec + DOT3_UAS_EXPIRY_TIME;

  /*
   * UAS의 유효성 여부를 업데이트한다.
   */
  dot3_UpdateUASAvailableUsingRxWSA(rcpi, entry);

  /*
   * 엔트리를 테이블에 추가한다.
   */
  TAILQ_INSERT_TAIL(&(table->head), entry, entries);
  table->num++;

  Log(kDot3LogLevel_Event, "Success to add UAS entry - %u entries present\n", table->num);
  return kDot3Result_Success;
}


/**
 * @brief UAS 엔트리를 업데이트한다.
 * @param[in] wsa 수신된 WSA 패킷데이터
 * @param[in] wsa_size 수신된 WSA 패킷데이터의 길이
 * @param[in] src_mac_addr WSA 송신지 MAC 주소
 * @param[in] wsa_type WSA type
 * @param[in] rcpi WSA 수신 세기
 * @param[in] tx_lat 송신자 위도. 값이 없을 경우 Unavailable을 전달한다.
 * @param[in] tx_lon 송신자 경도. 값이 없을 경우 Unavailable을 전달한다.
 * @param[in] tx_elev 송신자 고도. 값이 없을 경우 Unavailable을 전달한다.
 * @param[in] hdr 수신된 WSA 헤더
 * @param[in] wsi 수신된 WSA 내 Sevice Info
 * @param[in] wci 수신된 WSA 내 Channel Info
 * @param[in] wra 수신된 WSA 내 WRA (없을 경우 NULL)
 * @param[out] entry 업데이트될 UAS 엔트리 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_UpdateUASEntry(
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
  const struct Dot3WRA *wra,
  struct Dot3UASTableEntry *entry)
{
  Log(kDot3LogLevel_Event, "Update UAS entry\n");
  struct Dot3UAS *uas = &(entry->uas);

  /*
   * 기존에 수신했던 WSA와 동일한 WSA인 경우 RCPI 값과 수신카운트를 업데이트한다.
   */
  if ((entry->wsa_size == wsa_size) && (memcmp(entry->wsa, wsa, wsa_size) == 0)) {
    uas->rcpi = rcpi;
    if (entry->check_rx_cnt == true) {
      entry->rx_cnt_in_mgmt_timer_interval++;
    }
  }

  /*
   * 기존에 수신했던 WSA와 동일하지 않은 WSA인 경우(즉, WSA 내용이 변경된 경우), 정보 전체를 업데이트한다.
   *  - WSA 정보가 변경되었으므로, 수신카운트도 초기화한다.
   */
  else {
    dot3_ConstructUAS(src_mac_addr, wsa_type, rcpi, tx_lat, tx_lon, tx_elev, hdr, wsi, wci, wra, uas);
    entry->wsa_size = wsa_size;
    free(entry->wsa);
    entry->wsa = (uint8_t *)calloc(1, wsa_size);
    if (entry->wsa == NULL) {
      return -kDot3Result_NoMemory;
    }
    memcpy(entry->wsa, wsa, wsa_size);
    if ((wsi->extensions.wsa_cnt_threshold == true) && (wsi->extensions.wsa_cnt_threshold_interval == true)) {
      entry->check_rx_cnt = true;
      entry->rx_cnt_in_mgmt_timer_interval = 0;
    }
  }

  /*
   * 만기시각을 (재)설정한다.
   */
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  entry->expiry = ts.tv_sec + DOT3_UAS_EXPIRY_TIME;

  /*
   * UAS의 유효성 여부를 업데이트한다.
   */
  dot3_UpdateUASAvailableUsingRxWSA(rcpi, entry);

  Log(kDot3LogLevel_Event, "Success to update UAS entry\n");
  return kDot3Result_Success;
}


/**
 * @brief UAS 정보를 추가하거나 업데이트한다.
 * @param[in] table UAS 테이블
 * @param[in] wsa 수신된 WSA 패킷데이터
 * @param[in] wsa_size 수신된 WSA 패킷데이터의 길이
 * @param[in] src_mac_addr WSA 송신지 MAC 주소
 * @param[in] wsa_type WSA 유형
 * @param[in] rcpi WSA 수신 세기
 * @param[in] tx_lat WSA 송신지 위도
 * @param[in] tx_lon WSA 송신지 경도
 * @param[in] tx_elev WSA 송신지 고도
 * @param[in] hdr 수신된 WSA 내 헤더 정보
 * @param[in] wsi 수신된 WSA 내 Service Info
 * @param[in] wci 수신된 WSA 내 Channel Info
 * @param[in] wra 수신된 WSA 내 WRA (없을 경우 NULL)
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
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
  const struct Dot3WRA *wra)
{
  Log(kDot3LogLevel_Event, "Add or update UAS\n");

  /*
   * 동일한 송신지 MAC 주소, WSA ID, PSID를 갖는 UAS가 테이블에 이미 존재하는지 탐색하여;
   *  * 존재하지 않는 경우, 정보를 새롭게 추가한다.
   *  * 존재하는 경우, 정보를 업데이트한다.
   */
  int ret;
  struct Dot3UASTableEntry *entry = dot3_FindMatchedUAS(table, src_mac_addr, hdr->wsa_id, wsi->psid);
  if (entry == NULL) {
    ret = dot3_AddUASEntry(table, wsa, wsa_size, src_mac_addr, wsa_type, rcpi, tx_lat, tx_lon, tx_elev, hdr, wsi, wci, wra);
  } else {
    ret = dot3_UpdateUASEntry(wsa, wsa_size, src_mac_addr, wsa_type, rcpi, tx_lat, tx_lon, tx_elev, hdr, wsi, wci, wra, entry);
  }
  return ret;
}


/**
 * @brief 테이블 내 모든 UAS들을 삭제한다.
 * @param[in] table UAS 테이블
 */
void INTERNAL dot3_DeleteAllUASs(struct Dot3UASTable *table)
{
  Log(kDot3LogLevel_Event, "Delete all UASs\n");

  /*
   * 테이블 내 모든 UAS들을 삭제한다.
   */
  struct Dot3UASTableEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(table->head), entries, tmp) {
    TAILQ_REMOVE(&(table->head), entry, entries);
    if (entry->wsa) { free(entry->wsa); }
    free(entry);
  }
  table->num = 0;
}


/**
 * @brief UAS 테이블에 저장되어 있는 모든 UAS 정보(들)을 반환한다.
 * @param[in] table UAS 테이블
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 저장될 변수의 포인터
 * @return UAS 정보집합
 * @retval NULL: 실패
 */
struct Dot3UASSet INTERNAL * dot3_GetAllUASs(struct Dot3UASTable *table, int *err)
{
  Log(kDot3LogLevel_Event, "Get all UASs\n");

  /*
   * 반환을 위한 메모리를 할당한다.
   */
  Dot3UASNum uas_num = (table->num > kDot3UASNum_Max) ? kDot3UASNum_Max : table->num;
  struct Dot3UASSet *set = (struct Dot3UASSet *)calloc(1, sizeof(struct Dot3UASSet) + sizeof(struct Dot3UAS) * uas_num);
  if (set == NULL) {
    *err = -kDot3Result_NoMemory;
    return NULL;
  }

  /*
   * 테이블에 UAS 정보가 없으면 그냥 반환한다.
   */
  if (uas_num == 0) {
    Log(kDot3LogLevel_Event, "Success to get UASs - No UAS is in table\n");
    return set;
  }

  /*
   * 반환 메모리에 UAS 정보들을 복사한다.
   */
  set->num = uas_num;
  struct Dot3UASTableEntry *entry;
  struct Dot3UAS *uas;
  unsigned int num = 0;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    uas = set->uas + num++;
    memcpy(uas, &(entry->uas), sizeof(struct Dot3UAS));
    if (num >= uas_num) {
      break;
    }
  }

  Log(kDot3LogLevel_Event, "Success to get all UASs - %u UAS is returned\n", uas_num);
  return set;
}


/**
 * @brief UAS 테이블에 저장되어 있는 UAS 정보(들) 중 특정 PSID를 갖는 UAS 정보(들)을 반환한다.
 * @param[in] table UAS 테이블
 * @param[in] psid 찾고자 하는 PSID
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 저장될 변수의 포인터
 * @return UAS 정보집합
 * @retval NULL: 실패
 */
struct Dot3UASSet INTERNAL * dot3_GetUASsWithPSID(struct Dot3UASTable *table, Dot3PSID psid, int *err)
{
  Log(kDot3LogLevel_Event, "Get UASs with PSID %u\n", psid);

  /*
   * 반환을 위한 메모리를 할당한다.
   */
  Dot3UASNum uas_num = (table->num > kDot3UASNum_Max) ? kDot3UASNum_Max : table->num;
  struct Dot3UASSet *set = (struct Dot3UASSet *)calloc(1, sizeof(struct Dot3UASSet) + sizeof(struct Dot3UAS) * uas_num);
  if (set == NULL) {
    *err = -kDot3Result_NoMemory;
    return NULL;
  }

  /*
   * 테이블에 UAS 정보가 없으면 그냥 반환한다.
   */
  if (uas_num == 0) {
    Log(kDot3LogLevel_Event, "Success to get UASs - No UAS is in table\n");
    return set;
  }

  /*
   * 반환 메모리에 해당 PSID를 갖는 UAS 정보들을 복사한다.
   */
  struct Dot3UASTableEntry *entry;
  struct Dot3UAS *uas;
  unsigned int num = 0;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    if (entry->uas.psid == psid) {
      uas = set->uas + num++;
      memcpy(uas, &(entry->uas), sizeof(struct Dot3UAS));
    }
    if (num >= uas_num) {
      break;
    }
  }
  set->num = (num > uas_num) ? uas_num: num;
  struct Dot3UASSet *new_set = realloc(set, sizeof(struct Dot3UASSet) + sizeof(struct Dot3UAS) * set->num);
  if (new_set == NULL) {
    *err = -kDot3Result_NoMemory;
    free(set); return NULL;
  }

  Log(kDot3LogLevel_Event, "Success to get UASs - %u/%u UAS is returned\n", new_set->num, uas_num);
  return new_set;
}


/**
 * @brief UAS 테이블에 저장되어 있는 UAS 정보(들) 중 특정 송신지 MAC 주소를 갖는 UAS 정보(들)을 반환한다.
 * @param[in] table UAS 테이블
 * @param[in] addr 찾고자 하는 송신지 MAC 주소
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 저장될 변수의 포인터
 * @return UAS 정보집합
 * @retval NULL: 실패
 */
struct Dot3UASSet INTERNAL *
dot3_GetUASsWithSourceMACAddress(struct Dot3UASTable *table, const Dot3MACAddress addr, int *err)
{
  Log(kDot3LogLevel_Event, "Get UASs with %02X:%02X:%02X:%02X:%02X:%02X\n",
      addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

  /*
   * 반환을 위한 메모리를 할당한다.
   */
  Dot3UASNum uas_num = (table->num > kDot3UASNum_Max) ? kDot3UASNum_Max : table->num;
  struct Dot3UASSet *set = (struct Dot3UASSet *)calloc(1, sizeof(struct Dot3UASSet) + sizeof(struct Dot3UAS) * uas_num);
  if (set == NULL) {
    *err = -kDot3Result_NoMemory;
    return NULL;
  }

  /*
   * 테이블에 UAS 정보가 없으면 그냥 반환한다.
   */
  if (uas_num == 0) {
    Log(kDot3LogLevel_Event, "Success to get UASs - No UAS is in table\n");
    return set;
  }

  /*
   * 반환 메모리에 해당 송신지 MAC 주소를 갖는 UAS 정보들을 복사한다.
   */
  struct Dot3UASTableEntry *entry;
  struct Dot3UAS *uas;
  unsigned int num = 0;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    if (memcmp(entry->uas.src_mac_addr, addr, MAC_ALEN) == 0) {
      uas = set->uas + num++;
      memcpy(uas, &(entry->uas), sizeof(struct Dot3UAS));
    }
    if (num >= uas_num) {
      break;
    }
  }
  set->num = (num > uas_num) ? uas_num: num;
  struct Dot3UASSet *new_set = realloc(set, sizeof(struct Dot3UASSet) + sizeof(struct Dot3UAS) * set->num);
  if (new_set == NULL) {
    *err = -kDot3Result_NoMemory;
    free(set);
    return NULL;
  }

  Log(kDot3LogLevel_Event, "Success to get UASs - %u/%u UAS is returned\n", new_set->num, uas_num);
  return new_set;
}


/**
 * @brief UAS 테이블에 저장되어 있는 UAS 정보(들) 중 특정 PSID와 송신지 MAC 주소를 갖는 UAS 정보(들)을 반환한다.
 * @param[in] table UAS 테이블
 * @param[in] psid 찾고자 하는 PSID
 * @param[in] addr 찾고자 하는 송신지 MAC 주소
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 저장될 변수의 포인터
 * @return UAS 정보집합
 * @retval NULL: 실패
 */
struct Dot3UASSet INTERNAL *
dot3_GetUASsWithPSIDAndSourceMACAddress(struct Dot3UASTable *table, Dot3PSID psid, const Dot3MACAddress addr, int *err)
{
  Log(kDot3LogLevel_Event, "Get UASs with PSID %u and %02X:%02X:%02X:%02X:%02X:%02X\n",
      psid, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

  /*
   * 반환을 위한 메모리를 할당한다.
   */
  Dot3UASNum uas_num = (table->num > kDot3UASNum_Max) ? kDot3UASNum_Max : table->num;
  struct Dot3UASSet *set = (struct Dot3UASSet *)calloc(1, sizeof(struct Dot3UASSet) + sizeof(struct Dot3UAS) * uas_num);
  if (set == NULL) {
    *err = -kDot3Result_NoMemory;
    return NULL;
  }

  /*
   * 테이블에 UAS 정보가 없으면 그냥 반환한다.
   */
  if (uas_num == 0) {
    Log(kDot3LogLevel_Event, "Success to get UASs - No UAS is in table\n");
    return set;
  }

  /*
   * 반환 메모리에 해당 PSID와 송신지 MAC 주소를 갖는 UAS 정보들을 복사한다.
   */
  struct Dot3UASTableEntry *entry;
  struct Dot3UAS *uas;
  unsigned int num = 0;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    if ((entry->uas.psid == psid) && (memcmp(entry->uas.src_mac_addr, addr, MAC_ALEN) == 0)) {
      uas = set->uas + num++;
      memcpy(uas, &(entry->uas), sizeof(struct Dot3UAS));
    }
    if (num >= uas_num) {
      break;
    }
  }
  set->num = (num > uas_num) ? uas_num: num;
  struct Dot3UASSet *new_set = realloc(set, sizeof(struct Dot3UASSet) + sizeof(struct Dot3UAS) * set->num);
  if (new_set == NULL) {
    *err = -kDot3Result_NoMemory;
    free(set);
    return NULL;
  }

  Log(kDot3LogLevel_Event, "Success to get UASs - %u/%u UAS is returned\n", new_set->num, uas_num);
  return new_set;
}


/**
 * @brief UAS 테이블에 저장되어 있는 UAS 정보(들) 중 RCPI가 가장 큰 UAS 정보(들)을 저장하여 반환한다.
 * @param[in] table UAS 테이블
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 저장될 변수의 포인터
 * @return UAS 정보집합
 * @retval NULL: 실패
 */
struct Dot3UASSet INTERNAL * dot3_GetUASsWithMaxRCPI(struct Dot3UASTable *table, int *err)
{
  Log(kDot3LogLevel_Event, "Get UASs with max RCPI\n");

  /*
   * 반환을 위한 메모리를 할당한다.
   */
  Dot3UASNum uas_num = (table->num > kDot3UASNum_Max) ? kDot3UASNum_Max : table->num;
  struct Dot3UASSet *set = (struct Dot3UASSet *)calloc(1, sizeof(struct Dot3UASSet) + sizeof(struct Dot3UAS) * uas_num);
  if (set == NULL) {
    *err = -kDot3Result_NoMemory;
    return NULL;
  }

  /*
   * 테이블에 UAS 정보가 없으면 그냥 반환한다.
   */
  if (uas_num == 0) {
    Log(kDot3LogLevel_Event, "Success to get UASs - No UAS is in table\n");
    return set;
  }

  /*
   * 각 UAS 정보의 RCPI 중 가장 큰 RCPI를 찾는다.
   */
  struct Dot3UASTableEntry *entry;
  Dot3RCPI max_rcpi = kDot3RCPI_Min;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    if (entry->uas.rcpi > max_rcpi) {
      max_rcpi = entry->uas.rcpi;
    }
  }

  /*
   * 가장 큰 RCPI 값을 갖는 UAS 정보(들)을 반환 메모리에 복사한다.
   */
  struct Dot3UAS *uas;
  unsigned int num = 0;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    if (entry->uas.rcpi == max_rcpi) {
      uas = set->uas + num++;
      memcpy(uas, &(entry->uas), sizeof(struct Dot3UAS));
    }
  }
  set->num = (num > uas_num) ? uas_num: num;
  struct Dot3UASSet *new_set = realloc(set, sizeof(struct Dot3UASSet) + sizeof(struct Dot3UAS) * set->num);
  if (new_set == NULL) {
    *err = -kDot3Result_NoMemory;
    free(set);
    return NULL;
  }

  Log(kDot3LogLevel_Event, "Success to get UASs - %u/%u UAS is returned\n", new_set->num, uas_num);
  return new_set;
}
