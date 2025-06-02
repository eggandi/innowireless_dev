/** 
 * @file
 * @brief BSM 관련 기능을 구현한 파일
 * @date 2020-10-03
 * @author gyun
 */


// 시스템 헤더 파일
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"
#include "j29451-mib.h"


/**
 * @brief 랜덤값들을 생성한다.
 * @param[out] msg_cnt 랜덤하게 생성된 msgCnt 값이 저장될 변수 포인터
 * @param[out] id 랜덤하게 생성된 id가 저장될 버퍼
 * @param[out] addr 랜덤하게 생성된 MAC주소가 저장될 버퍼
 */
static inline void j29451_GenerateRandoms(unsigned int *msg_cnt, uint8_t *id, uint8_t *addr)
{
  uint8_t t[1 + J29451_TEMPORARY_ID_LEN + MAC_ALEN];
  j29451_GetRandomOcts(t, sizeof(t));
  *msg_cnt = (unsigned int)(t[0] % 128);
  memcpy(id, t + 1, J29451_TEMPORARY_ID_LEN);
  memcpy(addr, t + 1 + J29451_TEMPORARY_ID_LEN, MAC_ALEN);
}


/**
 * @brief BSM 수납 정보를 초기화한다.
 * @param[in] bsm_data BSM 수납 정보
 * @param[out] addr 랜덤하게 생성된 MAC주소가 저장될 버퍼
 */
void INTERNAL j29451_InitBSMData(struct J29451BSMData *bsm_data, uint8_t *addr)
{
  Log(kJ29451LogLevel_Event, "Initialize BSM data\n");
  memset(bsm_data, 0, sizeof(struct J29451BSMData));

  /*
   * 랜덤한 Temporary ID 및 첫 msg count, MAC 주소를 생성한다.
   */
  j29451_GenerateRandoms(&(bsm_data->msg_cnt), bsm_data->temporary_id, addr);

  /*
   * 다음번에 사용할 랜덤값을 미리 생성해 둔다.
   */
  j29451_GenerateAndStoreNextRandomPool(bsm_data);
}


/**
 * @brief BSM 수납 정보를 해제한다.
 * @param[in] bsm_data BSM 수납 정보
 */
void INTERNAL j29451_ReleaseBSMData(struct J29451BSMData *bsm_data)
{
  Log(kJ29451LogLevel_Event, "Release BSM data\n");
  memset(bsm_data, 0, sizeof(struct J29451BSMData));
}


/**
 * @brief ID 변경 시점(또는 최초 시점)의 시각과 좌표를 저장한다.
 * @param[in] current_msec 현재 시각(밀리초단위)
 * @param[in] gnss 현 시점의 GNSS 데이터
 */
void INTERNAL j29451_UpdateBSMIDChangeInitialPoint(uint64_t current_msec, struct J29451GNSSData *gnss)
{
  g_j29451_mib.bsm_tx.id_change.initial_time = current_msec;
  if (g_j29451_mib.obu.gnss.user_gnss_enable == true) {
    g_j29451_mib.bsm_tx.id_change.initial_pos.lat_deg = j29451_ConvertToGNSSRawLatitude(gnss->lat);
    g_j29451_mib.bsm_tx.id_change.initial_pos.lon_deg = j29451_ConvertToGNSSRawLongitude(gnss->lon);
  } else {
    g_j29451_mib.bsm_tx.id_change.initial_pos.lat_deg = gnss->lat_deg;
    g_j29451_mib.bsm_tx.id_change.initial_pos.lon_deg = gnss->lon_deg;
  }
}


/**
 * @brief ID 변경이 필요한지 확인한다.
 * @param[in] current_msec 현재 시각
 * @param[in] gnss 현 시점의 GNSS 데이터
 * @return ID 변경 필요 여부
 */
bool INTERNAL j29451_CheckBSMIDChange(uint64_t current_msec, struct J29451GNSSData *gnss)
{
  Log(kJ29451LogLevel_Event, "Check BSM id change\n");

  bool id_change = false;
  struct J29451BSMTx *bsm_tx = &(g_j29451_mib.bsm_tx);

  /*
   * 라이브러리 시작 후 BSM이 아직 전송된 적이 없으면 ID 변경은 필요 없으며, 시작 시점 및 좌표를 저장한다.
   * (좌표가 유효하지 않은 경우(=NaN) BSM이 전송되지 않는다)
   */
  if ((bsm_tx->id_change.initial_time == 0) ||
      isnan(g_j29451_mib.bsm_tx.id_change.initial_pos.lat_deg) ||
      isnan(g_j29451_mib.bsm_tx.id_change.initial_pos.lon_deg)) {
    j29451_UpdateBSMIDChangeInitialPoint(current_msec, gnss);
    return false;
  }

  /*
   * 현재 ID를 사용한 후로 특정 시간이 경과하고, 현재 ID를 사용하기 시작했을 때의 최초 좌표로부터 특정 거리 이상 벗어났으면,
   * ID를 변경한다.
   */
  if (current_msec >= bsm_tx->id_change.initial_time + bsm_tx->id_change.interval) {
    double current_lat, current_lon;
    double init_lat = bsm_tx->id_change.initial_pos.lat_deg;
    double init_lon = bsm_tx->id_change.initial_pos.lon_deg;
    if (g_j29451_mib.obu.gnss.user_gnss_enable == true) {
      current_lat = j29451_ConvertToGNSSRawLatitude(gnss->lat);
      current_lon = j29451_ConvertToGNSSRawLongitude(gnss->lon);
    } else {
      current_lat = gnss->lat_deg;
      current_lon = gnss->lon_deg;
    }

    if ((isnan(init_lat) == 0) && (isnan(init_lon) == 0) && (isnan(current_lat) == 0) && (isnan(current_lon) == 0)) {
      double dist = earth_distance(init_lat, init_lon, current_lat, current_lon);
      if (dist >= bsm_tx->id_change.dist_threshold) {
        id_change = true;
      }
    }
  }
  return id_change;
}


/**
 * @brief 다음번에 사용할 랜덤값(msgCount, temporary id, MAC 주소 하위 3바이트)들을 생성해서 저장해 둔다.
 * @param[in] bsm_data BSM 수납 정보
 */
void INTERNAL j29451_GenerateAndStoreNextRandomPool(struct J29451BSMData *bsm_data)
{
  uint8_t t[MAC_ALEN];
  pthread_mutex_lock(&(g_j29451_mib.mtx));

  // 랜덤값을 구한다.
  uint8_t next_id[J29451_TEMPORARY_ID_LEN], next_addr[MAC_ALEN];
  unsigned int next_msg_cnt;
  j29451_GenerateRandoms(&next_msg_cnt, next_id, next_addr);

  // 직전값과 중복될 경우 랜덤값을 다시 구한다.
  while(next_msg_cnt == bsm_data->randoms.msg_cnt) {
    j29451_GetRandomOcts(t, 1);
    next_msg_cnt = (unsigned int)(t[0] % 128);
  }
  while(memcmp(next_id, bsm_data->randoms.temporary_id, J29451_TEMPORARY_ID_LEN) == 0) {
    j29451_GetRandomOcts(t, J29451_TEMPORARY_ID_LEN);
    memcpy(next_id, t, J29451_TEMPORARY_ID_LEN);
  }
  while(memcmp(next_addr, bsm_data->randoms.addr, MAC_ALEN) == 0) {
    j29451_GetRandomOcts(t, MAC_ALEN);
    memcpy(next_addr, t, MAC_ALEN);
  }
  bsm_data->randoms.msg_cnt = next_msg_cnt;
  memcpy(bsm_data->randoms.temporary_id, next_id, J29451_TEMPORARY_ID_LEN);
  memcpy(bsm_data->randoms.addr, next_addr, MAC_ALEN);
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}
