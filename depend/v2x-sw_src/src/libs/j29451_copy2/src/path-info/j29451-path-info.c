/** 
  * @file 
  * @brief 
  * @date 2022-08-26 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"
#include "j29451-path-info.h"
#include "j29451-mib.h"


/**
 * @brief Path 정보를 초기화한다.
 * @param[in] info Path 정보
 */
void INTERNAL j29451_InitPathInfo(struct J29451PathInfo *info)
{
  memset(info, 0, sizeof(struct J29451PathInfo));
  TAILQ_INIT(&(info->ph.gnss_point_list.head));
  info->pp.radius_of_curve = kJ29451RadiusOfCurvature_Straight;
  j29451_InitPathPredictionCurvatureFilter();
  j29451_InitPathPredictionConfidenceFilter();
}


/**
 * @brief GNSS 포인트 정보 리스트를 비운다.
 */
static inline void j29451_FlushPathHistoryGNSSPointList(void)
{
  struct J29451PathHistoryGNSSPointList *list = &(g_j29451_mib.path.ph.gnss_point_list);
  struct J29451PathHistoryGNSSPointListEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    TAILQ_REMOVE(&(list->head), entry, entries);
    free(entry);
  }
  list->entry_num = 0;
  list->internal.p_start = list->internal.p_prev = list->internal.p_next = list->internal.p_recent = NULL;
}


/**
 * @brief Path 정보를 해제한다.
 * @param[in] info Path 정보
 */
void INTERNAL j29451_ReleasePathInfo(struct J29451PathInfo *info)
{
  j29451_FlushPathHistoryGNSSPointList();
  memset(info, 0, sizeof(struct J29451PathInfo));
}


/**
 * @brief GNSS 포인트 정보를 리스트에 추가한다.
 * @param[in] gnss_data 추가할 GNSS 정보
 * @param[in] is_ph_point GNSS 포인트 정보가 PH point인지 여부 (파일백업된 정보를 복원해서 저장할 때 사용된다)
 */
void INTERNAL j29451_PushGNSSPointInfo(struct J29451GNSSData *gnss_data, bool is_ph_point)
{
  struct J29451PathHistoryGNSSPointList *list = &(g_j29451_mib.path.ph.gnss_point_list);
  struct J29451PathHistoryGNSSPointListEntry *entry = calloc(1, sizeof(struct J29451PathHistoryGNSSPointListEntry));
  assert(entry); // 메모리 부족 시 어플리케이션 종료 후 재실행해야 함.
  memcpy(&(entry->point), gnss_data, sizeof(struct J29451GNSSData));
  entry->is_ph_point = is_ph_point;
  TAILQ_INSERT_TAIL(&(list->head), entry, entries);
  list->entry_num++;
  list->internal.p_recent = entry;
  Log(kJ29451LogLevel_Event,
      "Push GNSS point info (Total: %u) - time: %"PRIu64", msec: %u, lat: %d, lon: %d, speed: %u, yawrate: %d\n",
      list->entry_num, entry->point.time, entry->point.msec, entry->point.lat, entry->point.lon, entry->point.speed,
      entry->point.acceleration_set.yaw);
}


/**
 * @brief Path 정보(Path History & Path prediction)를 업데이트한다
 * @param[in] gnss_data 최신 GNSS 데이터
 * @return 최소개수 이상의 PH point가 생성되었는지 여부 (최소개수 이상의 PH point가 존재해야 BSM 송신이 가능하다)
 */
bool INTERNAL j29451_UpdatePathInfo(struct J29451GNSSData *gnss_data)
{
  Log(kJ29451LogLevel_Event, "Update path info\n");

#if defined(_TARGET_STD_VER_2016_)
  /*
   * 백업된 PH 정보가 존재하는 경우, Path 정보를 업데이트하지 않는다.
   * 재부팅 전 정보와 동일한 BSM을 전송하기 위해, Path 정보가 업데이트 되지 않게 한다.
   */
  if (g_j29451_mib.path.backup_ph_present == true) {
    Log(kJ29451LogLevel_Event, "Skip update - use backup info\n");
    return true;
  }
#endif

  /*
   * GNSS 포인트 리스트에 최신 포인트 정보를 추가한다.
   */
  j29451_PushGNSSPointInfo(gnss_data, false);

  /*
   * 갱신된 GNSS 포인트 리스트들을 이용하여 Path history 정보와 Path prediction 정보를 업데이트한다.
   */
  bool sufficient_ph_point = j29451_UpdatePathHistoryInfo();
  j29451_UpdatePathPredictionInfo();
  if (sufficient_ph_point == false) {
    Err("Insufficient PH point\n");
  }
  return sufficient_ph_point;
}
