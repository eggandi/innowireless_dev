/** 
  * @file 
  * @brief 인라인함수 정의
  * @date 2022-08-17 
  * @author gyun 
  */

#ifndef V2X_SW_J29451_INTERNAL_INLINE_H
#define V2X_SW_J29451_INTERNAL_INLINE_H


// 시스템 헤더 파일
#include <assert.h>
#include <math.h>


#ifndef RAD_2_DEG
#define RAD_2_DEG (57.2957795130823208767981548141051703)
#endif

#ifndef DEG_2_RAD
#define DEG_2_RAD (0.0174532925199432957692369076848861271)
#endif


/**
 * @brief timespec 정보를 밀리초단위 값으로 변환한다.
 * @param[in] ts timespec 정보
 * @return 밀리초단위 시간값
 */
static inline uint64_t j29451_ConvertTimespecToMilliseconds(struct timespec *ts)
{
  return ((uint64_t)(ts->tv_sec) * 1000) + ((uint64_t)(ts->tv_nsec) / 1000000);
}


/**
 * @brief 밀리초단위 리눅스 시간을 DSecond 값(분 내에서의 밀리초값)으로 변환한다.
 * @param[in] msec 밀리초단위 리눅스 시간
 * @return DSecond 값
 *
 * 100 단위로 반올림한다.
 */
static inline J29451DSecond j29451_ConvertMillisecondsToDSecond(uint64_t msec)
{
  return (J29451DSecond)(msec % (60 * 1000));
}


/**
 * @brief 소수점 도(decimal degree)를 라디언(radian)으로 변환한다.
 * @param[in] deg 변환할 도 값
 * @return 변환된 라디언 값
 */
static inline double j29451_ConvertDecimalDegreesToRadians(double deg)
{
  return (deg * DEG_2_RAD);
}


/**
 * @brief GNSS 입력 위도값을 2735 형식으로 변환한다. (1도 단위 -> 0.1 마이크로도 단위)
 * @param[in] lat GNSS 입력 위도값
 * @return 2735 형식의 위도값
 */
static inline J29451Latitude j29451_ConvertGNSSLatitude(double lat)
{
  J29451Latitude ret = kJ29451Latitude_Unavailable;
  if (isnan(lat) == 0) {
    ret = (J29451Latitude)(lat * (1e7));
    ret = (ret > kJ29451Latitude_Max) ? kJ29451Latitude_Max : ret;
    ret = (ret < kJ29451Latitude_Min) ? kJ29451Latitude_Min : ret;
  }
  return ret;
}


/**
 * @brief 2735 형식의 위도값을 도단위 형식으로 변환한다 (0.1 마이크로도 단위 -> 1도 단위)
 * @param[in] lat 2735 형식 위도값
 * @return 1도 단위 위도값
 */
static inline double j29451_ConvertToGNSSRawLatitude(J29451Latitude lat)
{
  double lat_raw = NAN;
  if ((lat >= kJ29451Latitude_Min) && (lat <= kJ29451Latitude_Max)) {
    lat_raw = (double)lat / 1e7;
  }
  return lat_raw;
}


/**
 * @brief GNSS 입력 경도값을 2735 형식으로 변환한다. (1도 단위 -> 0.1 마이크로도 단위)
 * @param[in] lon GNSS 입력 경도값
 * @return 2735 형식의 경도값
 */
static inline J29451Longitude j29451_ConvertGNSSLongitude(double lon)
{
  J29451Longitude ret = kJ29451Longitude_Unavailable;
  if (isnan(lon) == 0) {
    ret = (J29451Longitude)(lon * (1e7));
    ret = (ret > kJ29451Longitude_Max) ? kJ29451Longitude_Max : ret;
    ret = (ret < kJ29451Longitude_Min) ? kJ29451Longitude_Min : ret;
  }
  return ret;
}


/**
 * @brief 2735 형식의 경도값을 도단위 형식으로 변환한다 (0.1 마이크로도 단위 -> 1도 단위)
 * @param[in] lon 2735 형식 경도값
 * @return 1도 단위 경도값
 */
static inline double j29451_ConvertToGNSSRawLongitude(J29451Longitude lon)
{
  double lon_raw = NAN;
  if ((lon >= kJ29451Longitude_Min) && (lon <= kJ29451Longitude_Max)) {
    lon_raw = (double)lon / 1e7;
  }
  return lon_raw;
}


/**
 * @brief GNSS 입력 고도값을 2735 형식으로 변환한다. (1미터 단위 -> 0.1미터 단위)
 * @param[in] elev GNSS 입력 고도값
 * @return 2735 형식의 고도값
 */
static inline J29451Elevation j29451_ConvertGNSSElevation(double elev)
{
  J29451Elevation ret = kJ29451Elevation_Unavailable;
  if (isnan(elev) == 0) {
    ret = (J29451Elevation)(elev * 10/*=1/0.1*/);
    ret = (ret > kJ29451Elevation_Max) ? kJ29451Elevation_Max : ret;
    ret = (ret < kJ29451Elevation_Min) ? kJ29451Elevation_Min : ret;
  }
  return ret;
}


/**
 * @brief GNSS 입력 속도값을 2735 형식으로 변환한다. (1m/s 단위 -> 0.02m/s 단위)
 * @param[in] speed GNSS 입력 속도값
 * @return 2735 형식의 속도값
 */
static inline J29451Speed j29451_ConvertGNSSSpeed(double speed)
{
  J29451Speed ret = kJ29451Speed_Unavailable;
  if (isnan(speed) == 0) {
    ret = (J29451Speed)(speed * 50/*=1/0.02*/);
    ret = (ret > (J29451Speed)kJ29451Speed_Max) ? (J29451Speed)kJ29451Speed_Max : ret;
  }
  return ret;
}


/**
 * @brief GNSS 입력 헤딩값을 2735 형식으로 변환한다. (1도 단위 -> 0.0125도 단위)
 * @param[in] heading GNSS 입력 헤딩값
 * @return 2735 형식의 헤딩값
 */
static inline J29451Speed j29451_ConvertGNSSHeading(double heading)
{
  J29451Heading ret = kJ29451Heading_Unavailable;
  if (isnan(heading) == 0) {
    ret = (J29451Heading)(heading * 80/*=1/0.0125*/);
    ret = (ret > (J29451Heading)kJ29451Heading_Max) ? (J29451Heading)kJ29451Heading_Max : ret;
  }
  return ret;
}


/**
 * @brief GNSS 입력 semi-major axis accuracy 값을 2735 형식으로 변환한다. (1미터 단위 -> 0.05미터 단위)
 * @param[in] acc GNSS 입력 semi-major axis accuracy 값
 * @return 2735 형식의 semi-major axis accuracy 값
 */
static inline J29451SemiMajorAxisAccuracy j29451_ConvertGNSSSemiMajorAxisAccuracy(double acc)
{
  J29451SemiMajorAxisAccuracy ret = kJ29451SemiMajorAxisAccuracy_Unavailable;
  if (isnan(acc) == 0) {
    ret = (J29451SemiMajorAxisAccuracy)(acc * 20/*=1/0.05*/);
    ret = (ret > (J29451SemiMajorAxisAccuracy)kJ29451SemiMajorAxisAccuracy_Max)
          ? (J29451SemiMajorAxisAccuracy)kJ29451SemiMajorAxisAccuracy_Max : ret;
  }
  return ret;
}


/**
 * @brief GNSS 입력 semi-minor axis accuracy 값을 2735 형식으로 변환한다. (1미터 단위 -> 0.05미터 단위)
 * @param[in] acc GNSS 입력 semi-minor axis accuracy 값
 * @return 2735 형식의 semi-minor axis accuracy 값
 */
static inline J29451SemiMinorAxisAccuracy j29451_ConvertGNSSSemiMinorAxisAccuracy(double acc)
{
  J29451SemiMinorAxisAccuracy ret = kJ29451SemiMinorAxisAccuracy_Unavailable;
  if (isnan(acc) == 0) {
    ret = (J29451SemiMinorAxisAccuracy)(acc * 20/*=1/0.05*/);
    ret = (ret > (J29451SemiMinorAxisAccuracy)kJ29451SemiMinorAxisAccuracy_Max)
          ? (J29451SemiMinorAxisAccuracy)kJ29451SemiMinorAxisAccuracy_Max : ret;
  }
  return ret;
}


/**
 * @brief GNSS 입력 semi-major axis orientation 값을 2735 형식으로 변환한다. (1도 단위 -> 360/65535도 단위)
 * @param[in] orient GNSS 입력 semi-major axis orientation 값
 * @return 2735 형식의 semi-major axis orientation 값
 */
static inline J29451SemiMajorAxisOrientation j29451_ConvertGNSSSemiMajorAxisOrientation(double orient)
{
  J29451SemiMajorAxisOrientation ret = kJ29451SemiMajorAxisOrientation_Unavailable;
  if (isnan(orient) == 0) {
    ret = (J29451SemiMajorAxisOrientation)(orient * 182.0416660970/*=1/(360/65535)*/);
    ret = (ret > (J29451SemiMajorAxisOrientation)kJ29451SemiMajorAxisOrientation_Max)
          ? (J29451SemiMajorAxisOrientation)kJ29451SemiMajorAxisOrientation_Max : ret;
  }
  return ret;
}


/*
 * @brief GNSS 입력 종/횡방향 가속도값을 2735 형식으로 변환한다. (1 m/s^2 단위 -> 0.01 m/s^2 단위)
 * @param[in] acceleration GNSS 입력 가속도값
 * @return 2735 형식의 가속도값
 */
static inline J29451Acceleration j29451_ConvertGNSSAcceleration(double acceleration)
{
  J29451Acceleration ret = kJ29451Acceleration_Unavailable;
  if (isnan(acceleration) == 0) {
    ret = (J29451Acceleration)(acceleration * 100 /*=1/0.01*/);
    ret = (ret > (J29451Acceleration)kJ29451Acceleration_Max) ? (J29451Acceleration)kJ29451Acceleration_Max : ret;
    ret = (ret < (J29451Acceleration)kJ29451Acceleration_Min) ? (J29451Acceleration)kJ29451Acceleration_Min : ret;
  }
  return ret;
}


/**
 * @brief 2735 형식 종/횡방향 가속도값을 GNSS 입력 형식으로 변환한다. (0.01 m/s^2 단위 -> 1 m/s^2 단위)
 * @param[in] acc 2735 형식 종/횡방향 가속도값
 * @return GNSS 입력 형식 종/횡방향 가속도값
 */
static inline double j29451_ConvertToGNSSRawAcceleration(J29451Acceleration acc)
{
  return ((acc >= kJ29451Acceleration_Min) && (acc <= kJ29451Acceleration_Max)) ? ((double)acc / 100.0) : NAN;
}


/*
 * @brief GNSS 입력 수직방향 가속도값을 2735 형식으로 변환한다. (1 m/s^2 단위 -> 0.1962 m/s^2 단위(=0.02G 단위))
 * @param[in] acceleration GNSS 입력 가속도값
 * @return 2735 형식의 가속도값
 */
static inline J29451VerticalAcceleration j29451_ConvertGNSSVerticalAcceleration(double acceleration)
{
  J29451VerticalAcceleration ret = kJ29451VerticalAcceleration_Unavailable;
  if (isnan(acceleration) == 0) {
    ret = (J29451VerticalAcceleration)(acceleration * 5.0967 /*=1/0.1962*/);
    ret = (ret > (J29451VerticalAcceleration)kJ29451VerticalAcceleration_Max)
          ? (J29451VerticalAcceleration)kJ29451VerticalAcceleration_Max : ret;
    ret = (ret < (J29451VerticalAcceleration)kJ29451VerticalAcceleration_Min)
          ? (J29451VerticalAcceleration)kJ29451VerticalAcceleration_Min : ret;
  }
  return ret;
}


/*
 * @brief GNSS 입력 요율값을 2735 형식으로 변환한다. (1 deg/s 단위 -> 0.01 deg/s 단위)
 * @param[in] yaw_rate GNSS 입력 요율값
 * @return 2735 형식의 요율
 *
 * NOTE:: gps.h 파일에 정의된 attitude_t 내 gyro_z 변수를 사용하고 있다.
 * gps.h 파일의 주석에 따르면 gyro_z 변수는 1 deg/s^2의 단위를 가지지만, 우리는 그냥 1 deg/s로 사용한다.
 * 우리가 F9K용으로 수정한 gpsd에서도 이 변수를 1 deg/s 단위로 채운다.
 */
static inline J29451YawRate j29451_ConvertGNSSYawRate(double yaw_rate)
{
  J29451YawRate ret = kJ29451YawRate_Unavailable;
  if (isnan(yaw_rate) == 0) {
    ret = (J29451YawRate)(yaw_rate * 100 /*=1/0.01*/);
    ret = (ret > (J29451YawRate)kJ29451YawRate_Max) ? (J29451YawRate)kJ29451YawRate_Max : ret;
    ret = (ret < (J29451YawRate)kJ29451YawRate_Min) ? (J29451YawRate)kJ29451YawRate_Min : ret;
  }
  return ret;
}


/**
 * @brief 차량정보 중 hard braking 이벤트를 set 한다.
 * @param[out] veh 차량정보가 저장될 구조체 변수 포인터
 */
static inline void j29451_SetVehicleInfoHardBrakingEvent(struct J29451VehicleInfo *veh)
{
  veh->event.event.hard_braking = true;
  veh->event.set = true;
}


/**
 * @brief 차량정보 중 hard braking 이벤트를 clear 한다.
 * @param[out] veh 차량정보가 저장될 구조체 변수 포인터
 */
static inline void j29451_ClearVehicleInfoHardBrakingEvent(struct J29451VehicleInfo *veh)
{
  struct J29451VehicleEventFlags *event = &(veh->event.event);
  if (event->hard_braking == true) {
    event->hard_braking = false;
    veh->event.set = event->hazard_lights || event->stop_line_violation || event->abs_activated ||
                     event->traction_control_loss || event->stability_control_activated ||
                     event->hazardous_materials ||
                     event->hard_braking || event->lights_changed || event->wiper_changed || event->flat_tire ||
                     event->disabled_vehicle || event->airbag_deployment;
  }
}


/**
 * @brief 위도간 오프셋을 계산한다.
 * @param[in] anchor 오프셋 계산의 기준 위도
 * @param[in] target 오프셋 계산의 대상 위도
 * @return 오프셋 (=anchor-target)
 */
static inline J29451LatLonOffsetLL_B18 j29451_CalculateLatOffset(J29451Latitude anchor, J29451Latitude target)
{
  J29451LatLonOffsetLL_B18 offset = anchor - target;
  if (offset < kJ29451LatLonOffsetLL_B18_Min) {
    offset = kJ29451LatLonOffsetLL_B18_Min;
  } else if (offset > kJ29451LatLonOffsetLL_B18_Max) {
    offset = kJ29451LatLonOffsetLL_B18_Max;
  }
  return offset;
}


/**
 * @brief 경도간 오프셋을 계산한다.
 * @param[in] anchor 오프셋 계산의 기준 경도
 * @param[in] target 오프셋 계산의 대상 경도
 * @return 오프셋 (=anchor-target)
 */
static inline J29451LatLonOffsetLL_B18 j29451_CalculateLonOffset(J29451Longitude anchor, J29451Longitude target)
{
  J29451LatLonOffsetLL_B18 offset = anchor - target;
  if (offset < kJ29451LatLonOffsetLL_B18_Min) {
    offset = kJ29451LatLonOffsetLL_B18_Min;
  } else if (offset > kJ29451LatLonOffsetLL_B18_Max) {
    offset = kJ29451LatLonOffsetLL_B18_Max;
  }
  return offset;
}


/**
 * @brief 고도간 오프셋을 계산한다.
 * @param[in] anchor 오프셋 계산의 기준 고도
 * @param[in] target 오프셋 계산의 대상 고도
 * @return 오프셋 (=anchor-target)
 */
static inline J29451VertOffset_B12 j29451_CalculateElevOffset(J29451Elevation anchor, J29451Elevation target)
{
  J29451VertOffset_B12 offset = anchor - target;
  if (offset < kJ29451VertOffset_B12_Min) {
    offset = kJ29451VertOffset_B12_Min;
  } else if (offset > kJ29451VertOffset_B12_Max) {
    offset = kJ29451VertOffset_B12_Max;
  }
  return offset;
}


/**
 * @brief 시간 오프셋을 계산한다.
 * @param[in] anchor 오프셋 계산의 기준 시간(밀리초)
 * @param[in] target 오프셋 계산의 대상 시간(밀리초)
 * @return 오프셋 (=anchor-target)
 */
static inline J29451TimeOffset j29451_CalculateTimeOffset(uint64_t anchor, uint64_t target)
{
  J29451TimeOffset ret = kJ29451TimeOffset_Unavailable;
  if (anchor > target) {
    uint64_t offset = anchor - target;
    offset /= 10; // 단위변환 (밀리초 -> 10밀리초)
    if (offset > (uint64_t)kJ29451TimeOffset_Max) {
      offset = (uint64_t)kJ29451TimeOffset_Max;
    }
    assert((offset >= (uint64_t)kJ29451TimeOffset_Min) && (offset <= (uint64_t)kJ29451TimeOffset_Max));
    ret = (J29451TimeOffset)offset;
  }
  return ret;
}


/**
 * @brief 밀리초 단위의 현재 MONOTONIC 시간값을 반환한다.
 * @return 밀리초단위 시간값
 */
static inline uint64_t j29451_GetCurrentMsecMonotonic(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return j29451_ConvertTimespecToMilliseconds(&ts);
}


/**
 * @brief 밀리초단위 시간값을 특정 시간구간길이 내에서의 오프셋 값으로 변환한다.
|* @param[in] msec 밀리초단위 시간값
|* @param[in] interval 밀리초단위 시간구간길이
 * @return 오프셋 값
 */
static inline int64_t j29451_ConvertMsec2Offset(uint64_t msec, int64_t interval)
{
  return ((int64_t)msec % interval);
}


/**
 * @brief 현재 MONOTONIC 시간을 특정 시간구간길이 내에서의 오프셋 값으로 반환한다.
|* @param[in] interval 밀리초단위 시간구간길이
 * @return 오프셋 값
 */
static inline int64_t j29451_GetCurrentOffsetMonotonic(int64_t interval)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  uint64_t msec = j29451_ConvertTimespecToMilliseconds(&ts);
  return j29451_ConvertMsec2Offset(msec, interval);
}


/**
 * @brief 밀리초 단위의 현재 리얼타임 시간값(UTC 동기)을 반환한다.
 * @return 밀리초단위 시간값
 */
static inline uint64_t j29451_GetCurrentMsecReal(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return j29451_ConvertTimespecToMilliseconds(&ts);
}


#endif //V2X_SW_J29451_INTERNAL_INLINE_H
