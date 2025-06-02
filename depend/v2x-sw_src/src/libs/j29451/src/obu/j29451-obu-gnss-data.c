/**
 * @file
 * @brief GNSS 데이터 관련 기능 구현
 * @date 2023-04-03
 * @author gyun
 */


// 시스템 헤더파일
#include <unistd.h>

// 라이브러리 내부 헤더파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"


/**
 * @brief GNSS 데이터가 fix 상태인지 확인한다.
 * @param gpsdata gpsd로부터 읽어들인 GPS데이터
 * @return true
 * @return false
 */
static inline bool j29451_CheckGPSFix(struct gps_data_t *gps_data)
{
  if (gps_data->fix.mode < MODE_3D) {
    Err("GNSS is not fixed yet.\n");
    return false;
  }
  return true;
}


/**
 * @brief 신규 GNSS 데이터 업데이트시작 오프셋 값이 기존의 최적 GNSS 데이터 업데이트시작 오프셋보다 빠른 타이밍인지 여부를 반환한다.
 * @param[in] new_offset 신규 오프셋 값
 * @return true
 * @return false
 */
static inline bool j29451_CheckGNSSDataUpdateStartOffset(int64_t new_offset)
{
  struct J29451GNSSDataUpdateStartOffset *offset = &(g_j29451_mib.obu.gnss.offset);
  int64_t diff = new_offset - offset->optimal_start_offset;
  // wrap-around(100)
  if (diff < -50) {
    diff = (new_offset + 100) - offset->optimal_start_offset;
  } else if (diff > 50) {
    diff = new_offset - (offset->optimal_start_offset + 100);
  }
  return (diff < 0) ? true : false;
}


/**
 * @brief 최적 GNSS 데이터 업데이트시작 오프셋을 추정한다.
 * @param[in] gnss GNSS 데이터
 *
 * @note 이 함수의 동작은 각 epoch 구간마다 필수 GNSS 정보(NAV-PVT 등)가 항상 먼저 전달된다는 가정 하에 동작한다.
 *       만약, 추정 중에 특정 epoch 구간에서 필수 GNSS 정보가 누락되어 전달되지 않고 옵션 GNSS정보만 전달될 경우에는 오동작할 수 있다.
 */
static void j29451_EstimateOptimalGNSSDataUpdateStartOffset(struct J29451GNSSData *gnss)
{
  uint64_t mono_msec = j29451_GetCurrentMsecMonotonic();
  uint64_t real_msec = j29451_GetCurrentMsecReal();
  int64_t mono_offset = j29451_ConvertMsec2Offset(mono_msec, GNSS_EPOCH_INTERVAL_MSEC);

  struct J29451GNSSDataUpdateStartOffset *offset = &(g_j29451_mib.obu.gnss.offset);

  /*
   * 어플리케이션 실행 추 최초 1번째 업데이트 처리
   * 타이밍에 따라 epoch 구간내 업데이트 시작시점 데이터가 아닌 중간시점 데이터(예: NAV-EELL)가 가장 먼저 전달될 수 있으므로,
   * 정확한 업데이트시작 오프셋값을 구할 수 없을 수도 있다.
   * 따라서 첫번째 업데이트 정보는 무시해야 한다. 2번째 업데이트부터 정상적인 업데이트시작 오프셋을 구할 수 있다.
   */
  if (offset->estimate_cnt == 0) {
    offset->estimate_cnt++;
    offset->prev_update_start_epoch_msec = gnss->time;
    Log(kJ29451LogLevel_Err, "Estimate[%02ld] - current(R/M): %"PRIu64" / %"PRIu64", epoch: %"PRIu64"\n",
        offset->estimate_cnt - 1, real_msec, mono_msec, gnss->time);
  }
    /*
     * 2번째 업데이트 처리
     * 1번째 업데이트 epoch 구간의 다음번 epoch 구간 내 업데이트 정보를 처리한다.
     * 여기서는 정확한 업데이트시작 오프셋값을 구할 수 있다.
     */
  else if (offset->estimate_cnt == 1) {
    if (gnss->time > offset->prev_update_start_epoch_msec) { // epoch 구간내 첫번째 업데이트 정보(NAV-PVT)만 처리
      offset->optimal_start_offset = mono_offset; // 최적 업데이트시작 오프셋 저장
      offset->estimate_cnt++;
      offset->prev_update_start_epoch_msec = gnss->time;
      Log(kJ29451LogLevel_Err, "Estimate[%02ld] - current(R/M): %"PRIu64" / %"PRIu64", epoch: %"PRIu64", new: %03"PRId64", optimal: %03"PRId64" - First value!!\n",
          offset->estimate_cnt - 1, real_msec, mono_msec, gnss->time, mono_offset, offset->optimal_start_offset);
    }
  }
    /*
     * 3번째 이후의 업데이트 처리
     * 기존 최적 업데이트시작 오프셋과의 비교를 통해 최적 업데이트시작 오프셋값을 갱신한다.
     */
  else {
    if (gnss->time > offset->prev_update_start_epoch_msec) { // epoch 구간내 첫번째 업데이트 정보(NAV-PVT)만 처리
      if (j29451_CheckGNSSDataUpdateStartOffset(mono_offset)) { // 이번 오프셋이 기존보다 더 빠르면 최적 업데이트시작 오프셋 갱신
        offset->optimal_start_offset = mono_offset;
        Log(kJ29451LogLevel_Err, "Estimate[%02ld] - current(R/M): %"PRIu64" / %"PRIu64", epoch: %"PRIu64", new: %03"PRId64", optimal: %03"PRId64" - New value!!\n",
            offset->estimate_cnt, real_msec, mono_msec, gnss->time, mono_offset, offset->optimal_start_offset);
      } else {
        Log(kJ29451LogLevel_Err, "Estimate[%02ld] - current(R/M): %"PRIu64" / %"PRIu64", epoch: %"PRIu64", new: %03"PRId64", optimal: %03"PRId64"\n",
            offset->estimate_cnt, real_msec, mono_msec, gnss->time, mono_offset, offset->optimal_start_offset);
      }
      offset->estimate_cnt++;
      offset->prev_update_start_epoch_msec = gnss->time;
    }
  }

  /*
   * 추정횟수를 채우면, 추정이 완료되었음을 표시한다 (단순히 횟수를 채우면 완료되므로, 실제 추정이 완료되었는지 여부는 보장할 수 없다)
   */
  if (offset->estimate_cnt >= OPTINAL_GNSS_DATA_UPDATE_START_OFFSET_ESTIMATE_CNT) {
    offset->estimate_complete = true;
    Log(kJ29451LogLevel_Err, "Estimate[%02ld] - complete\n", offset->estimate_cnt);
  }
}


/**
 * @brief GNSS 데이터를 업데이트한다.
 * @param[in] gps_data gpsd로부터 읽어들인 GPS 데이터
 * @param[out] gnss 업데이트할 GNSS 데이터 정보
 */
static void j29451_UpdateGNSSData(struct gps_data_t *gps_data, struct J29451GNSSData *gnss)
{
  gnss->mode = gps_data->fix.mode;
  gnss->status = gps_data->fix.status;
  gnss->time = j29451_ConvertTimespecToMilliseconds(&(gps_data->fix.time));
  gnss->msec = j29451_ConvertMillisecondsToDSecond(gnss->time);
  gnss->lat = j29451_ConvertGNSSLatitude(gps_data->fix.latitude);
  gnss->lon = j29451_ConvertGNSSLongitude(gps_data->fix.longitude);
  gnss->elev = j29451_ConvertGNSSElevation(gps_data->fix.altHAE);
  gnss->speed = j29451_ConvertGNSSSpeed(gps_data->fix.speed);
  gnss->heading = j29451_ConvertGNSSHeading(gps_data->fix.track);
  gnss->pos_accuracy.semi_major = j29451_ConvertGNSSSemiMajorAxisAccuracy(gps_data->gst.smajor_deviation);
  gnss->pos_accuracy.semi_minor = j29451_ConvertGNSSSemiMinorAxisAccuracy(gps_data->gst.sminor_deviation);
  gnss->pos_accuracy.orientation = j29451_ConvertGNSSSemiMajorAxisOrientation(gps_data->gst.smajor_orientation);
  gnss->acceleration_set.lon = j29451_ConvertGNSSAcceleration(gps_data->attitude.acc_x);
  gnss->acceleration_set.lat = j29451_ConvertGNSSAcceleration(gps_data->attitude.acc_y);
  gnss->acceleration_set.vert = j29451_ConvertGNSSVerticalAcceleration(gps_data->attitude.acc_z);
  gnss->acceleration_set.yaw = j29451_ConvertGNSSYawRate(gps_data->attitude.gyro_z);
  gnss->acceleration_set.lon_raw = gps_data->attitude.acc_x;
  gnss->lat_deg = gps_data->fix.latitude;
  gnss->lon_deg = gps_data->fix.longitude;
  gnss->lat_rad = j29451_ConvertDecimalDegreesToRadians(gnss->lat_deg);
  gnss->lon_rad = j29451_ConvertDecimalDegreesToRadians(gnss->lon_deg);
}


/**
 * @brief GNSS 데이터 버퍼 엔트리에 저장된 epoch time의 값이 적절한지(직전 엔트리에 비해 epoch 구간길이만큼 증가했는지) 확인한다.
 * @param[in] entry GNSS 데이터 버퍼 엔트리
 * @return 적절한지 여부 (직전 엔트리가 없을 경우에도 true 반환)
 */
bool INTERNAL j29451_CheckGNSSDataBufEntryEpochTimeIncrease(struct J29451GNSSDataBufEntry *entry)
{
  struct J29451GNSSDataBufEntry *prev = TAILQ_PREV(entry, J29451GNSSDataBufEntryHead, entries);
  if (prev) {
    if ((entry->gnss.time - prev->gnss.time) != GNSS_EPOCH_INTERVAL_MSEC) {
      Err("Invalid updated epoch time increase - prev: %"PRIu64", recent: %"PRIu64"\n",
          prev->gnss.time, entry->gnss.time);
      return false;
    }
  }
  return true;
}


/**
 * @brief GNSS 데이터 버퍼 엔트리를 업데이트한다.
 * @param[in] gps_data gpsd로부터 읽어들인 GPS 데이터
 */
static void j29451_UpdateGNSSDataBufEntry(struct gps_data_t *gps_data)
{
  if (j29451_CheckGPSFix(gps_data)) {
    struct J29451GNSSDataBufEntry *entry = j29451_GetGNSSDataBufEntryToUpdate(gps_data);
    if (entry) {
      j29451_UpdateGNSSData(gps_data, &(entry->gnss));
      if (!g_j29451_mib.obu.gnss.offset.estimate_complete) {
        j29451_EstimateOptimalGNSSDataUpdateStartOffset(&(entry->gnss));
      }
      j29451_CheckGNSSDataBufEntryEpochTimeIncrease(entry);
    }
  }
}


/**
 * @brief GNSS 데이터 업데이트 쓰레드 루틴
 * @param[in] arg 사용되지 않는다.
 */
void INTERNAL * j29451_GNSSDataUpdateThread(void *arg)
{
  (void)arg;
  struct gps_data_t *gps_data = &(g_j29451_mib.obu.gnss.gps_data);

  Log(kJ29451LogLevel_Event, "Success to start GNSS data update thread\n");
  g_j29451_mib.obu.gnss.thread_running = true;

  /*
   * 대기(블록) 중 gpsd 정보가 갱신되면 GNSS 데이터를 업데이트한다.
   */
  int ret;
  while (gps_waiting(gps_data, GNSS_DATA_WAITING_USEC)) {
    if (g_j29451_mib.obu.gnss.thread_exit) {
      break;
    }
    ret = gps_read(gps_data, NULL, 0);
    if (ret == -1) {
      Err("Fail to gps_read() - code: %d, reason: %s\n", ret, gps_errstr(ret));
      sleep(1);
      continue;
    }

    pthread_mutex_lock(&(g_j29451_mib.mtx));
    j29451_UpdateGNSSDataBufEntry(gps_data);
    pthread_mutex_unlock(&(g_j29451_mib.mtx));
  }

  Log(kJ29451LogLevel_Event, "GNSS data update thread exit\n");
  g_j29451_mib.obu.gnss.thread_running = false;
  return NULL;
}


/**
 * @brief 전달된 오프셋 값이 필수 GNSS 데이터 업데이트 구간 내에 있는지 여부를 반환한다.
 * @param[in] offset epoch 구간길이(GNSS_EPOCH_INTERVAL_MSEC) 내에서의 오프셋 값
 * @return true
 * @return false
 */
bool INTERNAL j29451_InMandatoryGNSSDataUpdateInterval(int64_t offset)
{
  bool ret = false;
  int64_t min = g_j29451_mib.obu.gnss.offset.optimal_start_offset;
  int64_t max = (g_j29451_mib.obu.gnss.offset.optimal_start_offset + MANDATORY_GNSS_DATA_UPDATE_INTERVAL_MSEC) % 100;
  if (max > min) {
    if ((offset >= min) && (offset <= max)) {
      ret = true;
    }
  } else {
    if ((offset >= min) || (offset <= max)) {
      ret = true;
    }
  }
  return ret;
}


/**
 * @brief 최적 GNSS 데이터 업데이트 시작 오프셋 추정이 완료되었는지 확인힌다.
 * @return 완료되었는지 여부
 */
bool INTERNAL j29451_CheckOptimalGNSSDataUpdateStartOffsetEstimation(void)
{
  return g_j29451_mib.obu.gnss.offset.estimate_complete;
}


/**
 * @brief GNSS 데이터 선택모드를 설정한다. (최초 1회만 수행된다)
 */
void INTERNAL j29451_SetGNSSDataSelectionMode(void)
{
  if (g_j29451_mib.obu.gnss.gnss_data_sel_mode == kJ29451GNSSDataSelectionMode_Undef) {
    int64_t offset = j29451_GetCurrentOffsetMonotonic(GNSS_EPOCH_INTERVAL_MSEC);
    if (j29451_InMandatoryGNSSDataUpdateInterval(offset)) {
      Log(kJ29451LogLevel_Err, "Set GNSS data selection mode as SAFE\n");
      g_j29451_mib.obu.gnss.gnss_data_sel_mode = kJ29451GNSSDataSelectionMode_Safe;
    } else {
      Log(kJ29451LogLevel_Err, "Set GNSS data selection mode as RECENT\n");
      g_j29451_mib.obu.gnss.gnss_data_sel_mode = kJ29451GNSSDataSelectionMode_Recent;
    }
  }
}


/**
 * @brief GNSS 데이터 선택모드를 초기화한다.
 */
void INTERNAL j29451_InitGNSSDataSelectionMode(void)
{
  g_j29451_mib.obu.gnss.gnss_data_sel_mode = kJ29451GNSSDataSelectionMode_Undef;
}
