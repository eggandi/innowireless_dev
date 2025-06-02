/** 
 * @file
 * @brief GNSS 관련 기능을 구현한 파일
 * @date 2020-10-04
 * @author gyun
 */
 

// 시스템 헤더 파일
#include <math.h>
#include <string.h>
#include <stdlib.h>

// 라이브러리 의존 헤더 파일
#include "gps.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"
#ifdef _UNIT_TEST_
#include "j29451-test.h"
#endif


/**
 * @brief GNSS 정보를 초기화한다.
 * @param[in] info GNSS 정보
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int INTERNAL j29451_InitGNSSInfo(struct J29451GNSSInfo *info)
{
  Log(kJ29451LogLevel_Event, "Initialize GNSS info\n");

  /*
   * gpsd 인터페이스를 연다.
   */
#ifdef _UNIT_TEST_
#else
  int ret = gps_open("localhost", "2947", &(info->gps_data));
  if (ret) {
    Err("Fail to gps_open() - code: %d, reason: %s\n", ret, gps_errstr(ret));
    return -kJ29451Result_GPSFail;
  }
  (void)gps_stream(&(info->gps_data), WATCH_ENABLE | WATCH_NEWSTYLE, NULL);
#endif

  /*
   * GNSS 데이터 버퍼를 초기화한다.
   */
  j29451_InitGNSSDataBuf();

  /*
   * GNSS 정보를 초기화한다.
   */
  j29451_InitGNSSData(&(info->gnss_data));

  /*
   * 사용자 입력 GNSS 정보를 초기화한다.
   */
  info->user_gnss_enable = false;

  /*
   * 가속도 필터를 초기화한다.
   */
  j29451_InitBWLowPassFilter(&(info->accel_filter.lon), J29451_BW_FILTER_SAMPLING_FREQ, J29451_BW_FILTER_CUTOFF_FREQ);
  j29451_InitBWLowPassFilter(&(info->accel_filter.lat), J29451_BW_FILTER_SAMPLING_FREQ, J29451_BW_FILTER_CUTOFF_FREQ);
  j29451_InitBWLowPassFilter(&(info->accel_filter.vert), J29451_BW_FILTER_SAMPLING_FREQ, J29451_BW_FILTER_CUTOFF_FREQ);
  j29451_InitBWLowPassFilter(&(info->accel_filter.yaw), J29451_BW_FILTER_SAMPLING_FREQ, J29451_BW_FILTER_CUTOFF_FREQ);

  /*
   * GNSS 데이터 업데이트 쓰레드를 생성한다.
   */
  ret = -kJ29451Result_FailToCreateThread;
  if (pthread_create(&(info->thread), NULL, j29451_GNSSDataUpdateThread, NULL) == 0) {
    struct timespec req = {.tv_sec = 0, .tv_nsec = 10000000}, rem;
    while (info->thread_running == false) {
      nanosleep(&req, &rem);
    }
    ret = kJ29451Result_Success;
  }
  return ret;
}


/**
 * @brief GNSS 정보를 종료한다.
 * @param[in] info OBU 정보
 *
 * @note 뮤텍스 락 상태에서 호출 시 전송 쓰레드와의 데드락 상황에 빠질 수 있으므로, 언락 상태에서 호출되어야 한다.
 */
void INTERNAL j29451_ReleaseGNSSInfo(struct J29451GNSSInfo *info)
{
  Log(kJ29451LogLevel_Event, "Release GNSS info\n");

  /*
   * GNSS 데이터 업데이트 쓰레드를 종료시킨다.
   */
  if (info->thread_running == true) {
    info->thread_exit = true;
    pthread_join(info->thread, NULL);
  }

#ifdef _UNIT_TEST_
#else
  /*
   * gpsd 인터페이스 종료
   */
  gps_stream(&(info->gps_data), WATCH_DISABLE, NULL);
  gps_close(&(info->gps_data));
#endif

  /*
   * GNSS 데이터 버퍼를 비운다.
   */
  j29451_FlushGNSSDataBuf();
}


/**
 * @brief GNSS 데이터 정보를 초기화한다.
 * @param[in] gnss 초기화할 GNSS 데이터 정보
 */
void INTERNAL j29451_InitGNSSData(struct J29451GNSSData *gnss)
{
  memset(gnss, 0, sizeof(struct J29451GNSSData));
  gnss->mode = -1;
  gnss->status = -1;
  gnss->msec = kJ29451DSecond_Unavailable;
  gnss->lat = kJ29451Latitude_Unavailable;
  gnss->lon = kJ29451Longitude_Unavailable;
  gnss->elev = kJ29451Elevation_Unavailable;
  gnss->speed = kJ29451Speed_Unavailable;
  gnss->heading = kJ29451Heading_Unavailable;
  gnss->pos_accuracy.semi_major = kJ29451SemiMajorAxisAccuracy_Unavailable;
  gnss->pos_accuracy.semi_minor = kJ29451SemiMinorAxisAccuracy_Unavailable;
  gnss->pos_accuracy.orientation = kJ29451SemiMajorAxisOrientation_Unavailable;
  gnss->acceleration_set.lon = kJ29451Acceleration_Unavailable;
  gnss->acceleration_set.lat = kJ29451Acceleration_Unavailable;
  gnss->acceleration_set.vert = kJ29451VerticalAcceleration_Unavailable;
  gnss->acceleration_set.yaw = kJ29451YawRate_Unavailable;
  gnss->acceleration_set.lon_raw = NAN;
  gnss->lat_deg = NAN;
  gnss->lon_deg = NAN;
  gnss->lat_rad = NAN;
  gnss->lon_rad = NAN;
}


/**
 * @brief GNSS 데이터 정보가 BSM을 전송하기에 충분한지 확인한다.
 * @param[in] gnss GNSS 데이터 정보
 * @param[in] prev_gnss 직전 주기에 획득한 GNSS 데이터 정보
 * @retval true: BSM을 전송하기에 충분함
 * @retval false: BSM을 전송하기에 충분하지 않음
 *
 * SAE J2945/1 Table 19에 정의된 기준에 따라 판단한다.
 */
static bool j29451_CheckIfSufficientGNSSData(struct J29451GNSSData *gnss)
{
  if (gnss->lat == kJ29451Latitude_Unavailable) {
    Err("Insufficient GNSS data - latitude\n");
    return false;
  }
  if (gnss->lon == kJ29451Longitude_Unavailable) {
    Err("Insufficient GNSS data - longitude\n");
    return false;
  }
  if (gnss->elev == kJ29451Elevation_Unavailable) {
    Err("Insufficient GNSS data - elevation\n");
    return false;
  }
  if (gnss->pos_accuracy.semi_major == kJ29451SemiMajorAxisAccuracy_Unavailable) {
    Err("Insufficient GNSS data - semi-major axis accuracy\n");
    return false;
  }
  if (gnss->pos_accuracy.semi_minor == kJ29451SemiMinorAxisAccuracy_Unavailable) {
    Err("Insufficient GNSS data - semi-minor axis accuracy\n");
    return false;
  }
  if (gnss->pos_accuracy.orientation == kJ29451SemiMajorAxisOrientation_Unavailable) {
    Err("Insufficient GNSS data - semi-major axis orientation\n");
    return false;
  }
  if (gnss->speed == kJ29451Speed_Unavailable) {
    Err("Insufficient GNSS data - speed\n");
    return false;
  }
  if (gnss->heading == kJ29451Heading_Unavailable) {
    Err("Insufficient GNSS data - heading\n");
    return false;
  }
  // 인증(표준적합성 시험) 모드에서는 GNSS 모듈의 DR calibration이 되지 않은 상태이므로, 유효한 가속도값을 확보할 수 없다.
  // 따라서 항상 BSM 전송이 불가능하여 시험을 진행할 수 없다.
  // 이러한 현상을 피하기 위해 기본값을 설정하여 BSM 전송이 가능하도록 한다.
  if (g_j29451_mib.certification.activate == true) {
    if (gnss->acceleration_set.lon == kJ29451Acceleration_Unavailable) {
      Log(kJ29451LogLevel_Event, "Insufficient GNSS data - Force to set zero longitudinal acceleration\n");
      gnss->acceleration_set.lon = 0;
    }
    if (gnss->acceleration_set.yaw == kJ29451YawRate_Unavailable) {
      Log(kJ29451LogLevel_Event, "Insufficient GNSS data - Force to set zero(=straight) yawrate\n");
      gnss->acceleration_set.yaw = kJ29451YawRate_Straight;
    }
    return true;
  }
  // 일반동작 모드에서는 유효한 값이 확보되지 않으면 실패를 반환하여 BSM이 전송되지 않도록 한다.
  else {
    if (gnss->acceleration_set.lon == kJ29451Acceleration_Unavailable) {
#ifdef _DRIVING_TEST_
      Log(kJ29451LogLevel_Event, "Insufficient GNSS data - Force to set zero longitudinal acceleration\n");
      gnss->acceleration_set.lon = 0;
#else
      Err("Insufficient GNSS data - longitudinal acceleration\n");
      return false;
#endif
    }
    if (gnss->acceleration_set.yaw == kJ29451YawRate_Unavailable) {
#ifdef _DRIVING_TEST_
      Log(kJ29451LogLevel_Event, "Insufficient GNSS data - Force to set zero(=straight) yawrate\n");
      gnss->acceleration_set.yaw = kJ29451YawRate_Straight;
#else
      Err("Insufficient GNSS data - yawrate\n");
      return false;
#endif
    }
  }
  return true;
}


/**
 * @brief GNSS 데이터 중 가속도 데이터에 필터를 적용한다.
 * @param[in/out] gnss GNSS 데이터
 */
static inline void j29451_UpdateFilteredAccelerationSet(struct J29451GNSSData *gnss)
{
  if(gnss->acceleration_set.lon != kJ29451Acceleration_Unavailable) {
    float lon = j29451_BWLowPassFilter(&(g_j29451_mib.obu.gnss.accel_filter.lon), (float)gnss->acceleration_set.lon);
    lon *= (float)J29451_BW_FILTER_ADJUST_FACTOR;
    gnss->acceleration_set.lon = (J29451Acceleration)lon;
    gnss->acceleration_set.lon_raw = j29451_ConvertToGNSSRawAcceleration(gnss->acceleration_set.lon);
  }
  if(gnss->acceleration_set.lat != kJ29451Acceleration_Unavailable) {
    float lat = j29451_BWLowPassFilter(&(g_j29451_mib.obu.gnss.accel_filter.lat), (float)gnss->acceleration_set.lat);
    lat *= (float)J29451_BW_FILTER_ADJUST_FACTOR;
    gnss->acceleration_set.lat = (J29451Acceleration)lat;
  }
  if(gnss->acceleration_set.vert != kJ29451VerticalAcceleration_Unavailable) {
    float vert = j29451_BWLowPassFilter(&(g_j29451_mib.obu.gnss.accel_filter.vert), (float)gnss->acceleration_set.vert);
    vert *= (float)J29451_BW_FILTER_ADJUST_FACTOR;
    gnss->acceleration_set.vert = (J29451VerticalAcceleration)vert;
  }
  if (gnss->acceleration_set.yaw != kJ29451YawRate_Unavailable) {
    float yaw = j29451_BWLowPassFilter(&(g_j29451_mib.obu.gnss.accel_filter.yaw), (float)gnss->acceleration_set.yaw);
    yaw *= (float)J29451_BW_FILTER_ADJUST_FACTOR;
    gnss->acceleration_set.yaw = (J29451YawRate)yaw;
  }
}


#ifdef _TARGET_STD_VER_2016_
/**
 * @brief 백업된 GNSS 데이터를 획득한다.
 * @param[out] gnss GNSS 데이터가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
static int j29451_GetBackupGNSSData(struct J29451GNSSData *gnss)
{
  Log(kJ29451LogLevel_Event, "Get backup GNSS data\n");

  /*
   * 백업 GNSS 포인트 정보 리스트 중 마지막(=최신) 포인트 정보를 반환한다.
   */
  struct J29451PathHistoryGNSSPointList *list = &(g_j29451_mib.path.ph.gnss_point_list);
  struct J29451PathHistoryGNSSPointListEntry *recent = TAILQ_LAST(&(list->head), J29451PathHistoryGNSSPointListEntryHead);
  memcpy(gnss, &(recent->point), sizeof(struct J29451GNSSData));

  /*
   * 해당 포인트 정보를 MIB 상에 최신 정보로 저장한다.
   */
  memcpy(&(g_j29451_mib.obu.gnss.gnss_data), gnss, sizeof(struct J29451GNSSData));

  /*
   * 필수 데이터가 모두 유효한지 확인한다 (실제로는 유효하지 않는 경우가 없어야 한다 -> 유효한 정보만 백업되었을 것이므로)
   */
  if (j29451_CheckIfSufficientGNSSData(gnss) == false) {
    Err("Backup GNSS data is insufficient\n");
    return -kJ29451Result_InsufficientData;
  }
  return kJ29451Result_Success;
}
#endif


/**
 * @brief User GNSS 데이터를 획득한다.
 * @param[out] gnss GNSS 데이터가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
static int j29451_GetUserGNSSData(struct J29451GNSSData *gnss)
{
  Log(kJ29451LogLevel_Event, "Get user GNSS data\n");

  /*
   * 최신 User GNSS 데이터를 반환한다.
   */
  memcpy(gnss, &(g_j29451_mib.obu.gnss.gnss_data), sizeof(struct J29451GNSSData));

  /*
   * GNSS 데이터 획득시간을 현 시점으로 설정한다.
   */
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  gnss->time = j29451_ConvertTimespecToMilliseconds(&ts);
  gnss->msec = j29451_ConvertMillisecondsToDSecond(gnss->time);

  /*
   * 필수 데이터가 모두 유효한지 확인한다.
   *  - TS에 의해 User GNSS data가 설정되므로, TP 실행 초반에는 일부 정보가 유효하지 않을 수 있지만 결국 모두 유효해 져야 한다.
   */
  if (j29451_CheckIfSufficientGNSSData(gnss) == false) {
    Err("User GNSS data is insufficient\n");
    return -kJ29451Result_InsufficientData;
  }

  return kJ29451Result_Success;
}


/**
 * @brief gpsd가 제공하는 GNSS 데이터를 획득한다.
 * @param[out] gnss GNSS 데이터가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */

static int j29451_GetGNSSDataFromGPSD(struct J29451GNSSData *gnss)
{
  Log(kJ29451LogLevel_Event, "Get GNSS data from gpsd\n");
#ifdef _UNIT_TEST_
  ++g_test_gps_data_idx;
  struct J29451TestGPSData *gps_data = &(g_j29451_mib.obu.gnss.gps_data);
  memcpy(gps_data, &(g_test_gps_data[g_test_gps_data_idx]), sizeof(struct J29451TestGPSData));
  uint64_t gnss_time = j29451_ConvertTimespecToMilliseconds(&(gps_data->fix.time));

  /*
   * gpsd 데이터로부터 GNSS 데이터를 저장한다.
   */
  gnss->time = gnss_time;
  gnss->msec = j29451_ConvertMillisecondsToDSecond(gnss->time);
  if (gps_data->fix.mode >= MODE_NO_FIX) {
    if (gps_data->fix.mode >= MODE_2D) {
      gnss->lat = j29451_ConvertGNSSLatitude(gps_data->fix.latitude);
      gnss->lon = j29451_ConvertGNSSLongitude(gps_data->fix.longitude);
      gnss->speed = j29451_ConvertGNSSSpeed(gps_data->fix.speed);
      gnss->heading = j29451_ConvertGNSSHeading(gps_data->fix.track);
      gnss->lat_deg = gps_data->fix.latitude;
      gnss->lon_deg = gps_data->fix.longitude;
      gnss->lat_rad = j29451_ConvertDecimalDegreesToRadians(gnss->lat_deg);
      gnss->lon_rad = j29451_ConvertDecimalDegreesToRadians(gnss->lon_deg);
      gnss->elev = j29451_ConvertGNSSElevation(gps_data->fix.altHAE);
    }
  }
  gnss->pos_accuracy.semi_major = j29451_ConvertGNSSSemiMajorAxisAccuracy(gps_data->gst.smajor_deviation);
  gnss->pos_accuracy.semi_minor = j29451_ConvertGNSSSemiMinorAxisAccuracy(gps_data->gst.sminor_deviation);
  gnss->pos_accuracy.orientation = j29451_ConvertGNSSSemiMajorAxisOrientation(gps_data->gst.smajor_orientation);
  gnss->acceleration_set.lon = j29451_ConvertGNSSAcceleration(gps_data->attitude.acc_x);
  gnss->acceleration_set.lat = j29451_ConvertGNSSAcceleration(gps_data->attitude.acc_y);
  gnss->acceleration_set.vert = j29451_ConvertGNSSVerticalAcceleration(gps_data->attitude.acc_z);
  gnss->acceleration_set.yaw = j29451_ConvertGNSSYawRate(gps_data->attitude.gyro_z);
  gnss->acceleration_set.lon_raw = gps_data->attitude.acc_x;

#else

  /*
   * 처리할 GNSS 데이터 버퍼 엔트리를 가져와서 GNSS 데이터를 반환변수에 복사한다.
   */
  struct J29451GNSSDataBufEntry *entry = j29451_GetGNSSDataBufEntryToProcess();
  if (!entry) {
    Err("Fail to get GNSS data buf entry\n");
    return -kJ29451Result_InsufficientData;
  }

#endif // _UNIT_TEST_

  /*
   * GNSS 데이터가 BSM을 전송할 수 있을만큼 충분하지 않으면 실패를 반환한다.
   */
  if (j29451_CheckIfSufficientGNSSData(gnss) == false) {
    Err("GNSS data from gpsd is insufficient\n");
    return -kJ29451Result_InsufficientData;
  }

  /*
   * 가속도 데이터에 필터를 적용한다.
   */
  j29451_UpdateFilteredAccelerationSet(gnss);

  return kJ29451Result_Success;
}


/**
 * @brief 최신 GNSS 데이터를 획득한다.
 * @param[out] gnss GNSS 데이터가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int INTERNAL j29451_GetCurrentGNSSData(struct J29451GNSSData *gnss)
{
  int ret;
  Log(kJ29451LogLevel_Event, "Get current GNSS data\n");

#ifdef _TARGET_STD_VER_2016_
  /*
   * 백업된 PH 정보가 존재할 경우, GNSS 정보 리스트의 가장 마지막 정보를 반환한다.
   *  - 재부팅 전 정보와 동일한 BSM을 전송하기 위해서 새로운 GNSS 정보를 사용하지 않는다.
   */
  if (g_j29451_mib.path.backup_ph_present == true) {
    ret = j29451_GetBackupGNSSData(gnss);
    if (ret < 0) {
      // 백업 GNSS 데이터를 사용할 수 없으면 해당 데이터는 포기한다 -> 다음 주기부터는 새로 입력되는 데이터가 사용된다.
      g_j29451_mib.path.backup_ph_present = false;
      return ret;
    }

    // Heading 값 latching 여부룰 결정하고, 그에 따른 Heading 값을 반환한다.
    j29451_UpdateGNSSHeadingLatch(gnss->speed, gnss->heading); // heading 값 latching 여부 업데이트
    if (g_j29451_mib.obu.gnss.heading_latch.latched == true) { // heading 값이 latching 상태이면, 잠긴 heading 값으로 변경
      gnss->heading = g_j29451_mib.obu.gnss.heading_latch.heading;
    }

    return kJ29451Result_Success;
  }
#endif

  /*
   * 사용자 입력 GNSS 데이터 사용이 활성화된 경우, 사용자 입력 GNSS 정보를 반환한다.
   * 그렇지 않은 경우, 내부 GNSS 데이터(from gpsd)를 반환한다.
   */
  if (g_j29451_mib.obu.gnss.user_gnss_enable == true) {
    ret = j29451_GetUserGNSSData(gnss);
  } else {
    ret = j29451_GetGNSSDataFromGPSD(gnss);
  }
  if (ret < 0) {
    return ret;
  }

  /*
   * Heading 값 latching 여부룰 결정하고, 그에 따른 Heading 값을 반환한다.
   */
  j29451_UpdateGNSSHeadingLatch(gnss->speed, gnss->heading); // heading 값 latching 여부 업데이트
  if (g_j29451_mib.obu.gnss.heading_latch.latched == true) { // heading 값이 latching 상태이면, 잠긴 heading 값으로 변경
    gnss->heading = g_j29451_mib.obu.gnss.heading_latch.heading;
  }

  return kJ29451Result_Success;
}


/**
 * @brief 속도값에 따라 Heading 값의 latching 여부룰 설정한다.
 * @param[in] speed 현재 속도값
 * @param[in] heading 현재 heading 값
 */
void INTERNAL j29451_UpdateGNSSHeadingLatch(J29451Speed speed, J29451Heading heading)
{
  /*
   * 라이브러리 초기화 후 첫 호출 시, 속도가 기준값 이하이면 latching 한다.
   * latching된 헤딩값은 현시점의 헤딩값을 사용한다.
   */
  if (g_j29451_mib.obu.gnss.heading_latch.initialized == false) {
    g_j29451_mib.obu.gnss.heading_latch.initialized = true;
    if ((double)speed < J29451_SPEED_THRESH_LATCH_HEADING) {
      g_j29451_mib.obu.gnss.heading_latch.latched = true;
      g_j29451_mib.obu.gnss.heading_latch.heading = heading;
      Log(kJ29451LogLevel_Event, "Latching heading as %u - initial speed(%u) is low\n", heading, speed);
    }
  }
  else {
    /*
     * 현재 latching 상태일 경우, 속도값이 unlatch 임계값을 초과하면 latching 상태를 해제한다.
     */
    if (g_j29451_mib.obu.gnss.heading_latch.latched == true) {
      if (speed > J29451_SPEED_THRESH_UNLATCH_HEADING) {
        g_j29451_mib.obu.gnss.heading_latch.latched = false;
        Log(kJ29451LogLevel_Event, "Unlatching heading - current speed: %u\n", speed);
      }
    }

      /*
       * 현재 unlatching 상태일 경우, 직전 속도값은 latch 임계값보다 크고 현재 속도값이 latch 임계값보다 작으면,
       * latching 상태로 설정한다.
       */
    else {
      if (((double)(g_j29451_mib.obu.gnss.heading_latch.prev_speed) >= J29451_SPEED_THRESH_LATCH_HEADING) &&
          ((double)speed < J29451_SPEED_THRESH_LATCH_HEADING)) {
        g_j29451_mib.obu.gnss.heading_latch.latched = true;
        g_j29451_mib.obu.gnss.heading_latch.heading = g_j29451_mib.obu.gnss.heading_latch.prev_heading;
        Log(kJ29451LogLevel_Event, "Latching heading as %u - current speed: %u, prev speed: %u\n",
            g_j29451_mib.obu.gnss.heading_latch.heading, speed, g_j29451_mib.obu.gnss.heading_latch.prev_speed);
      }
    }
  }
  g_j29451_mib.obu.gnss.heading_latch.prev_speed = speed;
  g_j29451_mib.obu.gnss.heading_latch.prev_heading = heading;
}


#ifdef _TARGET_STD_VER_2020_
/**
 * @brief Heading 값 latching 상태를 복원한다. 본 함수는 시스템 시작 시의 백업정보 로딩시에만 한번 호출되어야 한다.
 * @param[in] speed 백업된 속도값
 * @param[in] heading 백업된 heading 값
 */
void INTERNAL j29451_RestoreGNSSHeadingLatch(J29451Speed speed, J29451Heading heading)
{
  Log(kJ29451LogLevel_Event, "Restore GNSS heading latch - backup speed: %u, backup heading: %u\n", speed, heading);
  if (speed < J29451_SPEED_THRESH_LATCH_HEADING) {
    g_j29451_mib.obu.gnss.heading_latch.initialized = true;
    g_j29451_mib.obu.gnss.heading_latch.latched = true;
    g_j29451_mib.obu.gnss.heading_latch.heading = heading;
    Log(kJ29451LogLevel_Event, "Latch backup heading(%u)\n", heading);
  } else {
    g_j29451_mib.obu.gnss.heading_latch.initialized = false;
    g_j29451_mib.obu.gnss.heading_latch.latched = false;
    g_j29451_mib.obu.gnss.heading_latch.heading = kJ29451Heading_Unavailable;
    Log(kJ29451LogLevel_Event, "Unlatch backup heading\n");
  }
  g_j29451_mib.obu.gnss.heading_latch.prev_speed = speed;
  g_j29451_mib.obu.gnss.heading_latch.heading = heading;
}
#endif
