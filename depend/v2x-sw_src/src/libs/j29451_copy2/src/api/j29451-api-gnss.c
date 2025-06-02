/** 
 * @file
 * @brief GNSS 관련 정보를 설정하는 API를 구현한 파일
 * @date 2020-10-09
 * @author gyun
 */

// 라이브러리 헤더 파일
#include "j29451/j29451-types.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"
#include "j29451-mib.h"


/**
 * @brief 사용자 GNSS 데이터의 사용을 활성화한다(상세 내용은 API 매뉴얼 참조).
 */
void OPEN_API J29451_EnableUserGNSSData(void)
{
  Log(kJ29451LogLevel_Event, "Enable user GNSS data\n");

  pthread_mutex_lock(&(g_j29451_mib.mtx));

  g_j29451_mib.obu.gnss.user_gnss_enable = true;

  /*
   * 사용자 입력 GNSS 데이터를 초기화한다.
   */
  j29451_InitGNSSData(&(g_j29451_mib.obu.gnss.gnss_data));

  /*
   * 기존 Path 정보를 제거하고 초기화한다.
   */
  j29451_ReleasePathInfo(&(g_j29451_mib.path));
  j29451_InitPathInfo(&(g_j29451_mib.path));

  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief 사용자 GNSS 데이터의 사용을 비활성화한다(상세 내용은 API 매뉴얼 참조).
 */
void OPEN_API J29451_DisableUserGNSSData(void)
{
  Log(kJ29451LogLevel_Event, "Disable user GNSS data\n");

  pthread_mutex_lock(&(g_j29451_mib.mtx));

  /*
   * 기존 Path 정보를 제거하고 초기화한다.
   */
  j29451_ReleasePathInfo(&(g_j29451_mib.path));
  j29451_InitPathInfo(&(g_j29451_mib.path));

  g_j29451_mib.obu.gnss.user_gnss_enable = false;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief 위도를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] lat 위도
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetUserGNSSLatitude(J29451Latitude lat)
{
  Log(kJ29451LogLevel_Event, "Set user GNSS latitude: %d\n", lat);

  if ((lat < kJ29451Latitude_Min) || (lat > kJ29451Latitude_Unavailable)) {
    Err("Fail to set user GNSS latitude - invalid latitude: %d\n", lat);
    return -kJ29451Result_InvalidParameters;
  }

  int ret;
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  if (g_j29451_mib.obu.gnss.user_gnss_enable == true) {
    struct J29451GNSSData *data = &(g_j29451_mib.obu.gnss.gnss_data);
    data->lat = lat;
    data->lat_deg = j29451_ConvertToGNSSRawLatitude(lat);
    data->lat_rad = j29451_ConvertDecimalDegreesToRadians(data->lat_deg);
    ret = kJ29451Result_Success;
  } else {
    Err("Fail to set user GNSS latitude - user GNSS data is not allowed\n");
    ret = -kJ29451Result_UserGNSSDataNotAllowed;
  }
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return ret;
}


/**
 * @brief 경도를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] lon 경도
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetUserGNSSLongitude(J29451Longitude lon)
{
  Log(kJ29451LogLevel_Event, "Set user GNSS longitude: %d\n", lon);

  if ((lon < kJ29451Longitude_Min) || (lon > kJ29451Longitude_Unavailable)) {
    Err("Fail to set user GNSS longitude - invalid longitude: %d\n", lon);
    return -kJ29451Result_InvalidParameters;
  }

  int ret;
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  if (g_j29451_mib.obu.gnss.user_gnss_enable == true) {
    struct J29451GNSSData *data = &(g_j29451_mib.obu.gnss.gnss_data);
    data->lon = lon;
    data->lon_deg = j29451_ConvertToGNSSRawLongitude(lon);
    data->lon_rad = j29451_ConvertDecimalDegreesToRadians(data->lon_deg);
    ret = kJ29451Result_Success;
  } else {
    Err("Fail to set user GNSS longitude - user GNSS data is not allowed\n");
    ret = -kJ29451Result_UserGNSSDataNotAllowed;
  }
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return ret;
}


/**
 * @brief 고도를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] elev 고도
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetUserGNSSElevation(J29451Elevation elev)
{
  Log(kJ29451LogLevel_Event, "Set user GNSS elevation: %d\n", elev);

  if ((elev < kJ29451Elevation_Unavailable) || (elev > kJ29451Elevation_Max)) {
    Err("Fail to set user GNSS elevation - invalid elevation: %d\n", elev);
    return -kJ29451Result_InvalidParameters;
  }

  int ret;
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  if (g_j29451_mib.obu.gnss.user_gnss_enable == true) {
    g_j29451_mib.obu.gnss.gnss_data.elev = elev;
    ret = kJ29451Result_Success;
  } else {
    Err("Fail to set user GNSS elevation - user GNSS data is not allowed\n");
    ret = -kJ29451Result_UserGNSSDataNotAllowed;
  }
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return ret;
}


/**
 * @brief 속도를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] speed 속도
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetUserGNSSSpeed(J29451Speed speed)
{
  Log(kJ29451LogLevel_Event, "Set user GNSS speed: %u\n", speed);

  if (speed > kJ29451Speed_Unavailable) {
    Err("Fail to set user GNSS speed - invalid speed: %d\n", speed);
    return -kJ29451Result_InvalidParameters;
  }

  int ret;
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  if (g_j29451_mib.obu.gnss.user_gnss_enable == true) {
    g_j29451_mib.obu.gnss.gnss_data.speed = speed;
    ret = kJ29451Result_Success;
  } else {
    Err("Fail to set user GNSS speed - user GNSS data is not allowed\n");
    ret = -kJ29451Result_UserGNSSDataNotAllowed;
  }
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return ret;
}


/**
 * @brief 헤딩을 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] heading 헤딩
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetUserGNSSHeading(J29451Heading heading)
{
  Log(kJ29451LogLevel_Event, "Set user GNSS heading: %u\n", heading);

  if (heading > kJ29451Heading_Unavailable) {
    Err("Fail to set user GNSS heading - invalid heading: %d\n", heading);
    return -kJ29451Result_InvalidParameters;
  }

  int ret;
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  if (g_j29451_mib.obu.gnss.user_gnss_enable == true) {
    g_j29451_mib.obu.gnss.gnss_data.heading = heading;
    ret = kJ29451Result_Success;
  } else {
    Err("Fail to set user GNSS heading - user GNSS data is not allowed\n");
    ret = -kJ29451Result_UserGNSSDataNotAllowed;
  }
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return ret;
}


/**
 * @brief 헤딩을 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] semi_major Semi major axis accuracy
 * @param[in] semi_minor Semi minor axis accuracy
 * @param[in] orientation Semi major axis orientation
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetUserGNSSPositionalAccuracy(
  J29451SemiMajorAxisAccuracy semi_major,
  J29451SemiMinorAxisAccuracy semi_minor,
  J29451SemiMajorAxisOrientation orientation)
{
  Log(kJ29451LogLevel_Event, "Set user GNSS positional accuracy - smajor: %u, sminor: %u, orientation: %u\n",
      semi_major, semi_minor, orientation);

  if (semi_major > kJ29451SemiMajorAxisAccuracy_Unavailable) {
    Err("Fail to set user GNSS positional accuracy - invalid semi-major: %u\n", semi_major);
    return -kJ29451Result_InvalidParameters;
  }
  if (semi_minor > kJ29451SemiMinorAxisAccuracy_Unavailable) {
    Err("Fail to set user GNSS positional accuracy - invalid semi-minor: %u\n", semi_minor);
    return -kJ29451Result_InvalidParameters;
  }
  if (orientation > kJ29451SemiMajorAxisOrientation_Unavailable) {
    Err("Fail to set user GNSS positional accuracy - invalid orientation: %u\n", orientation);
    return -kJ29451Result_InvalidParameters;
  }

  int ret;
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  if (g_j29451_mib.obu.gnss.user_gnss_enable == true) {
    g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_major = semi_major;
    g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_minor = semi_minor;
    g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.orientation = orientation;
    ret = kJ29451Result_Success;
  } else {
    Err("Fail to set user GNSS positional accuracy - user GNSS data is not allowed\n");
    ret = -kJ29451Result_UserGNSSDataNotAllowed;
  }
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return ret;
}


/**
 * @brief 차량의 4방향 가속정보를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] lon 종방향 가속도
 * @param[in] lat 횡방향 가속도
 * @param[in] vert 수직 가속도
 * @param[in] yaw yaw rate
 */
void OPEN_API J29451_SetUserGNSSAccelerationSet4Way(
  J29451Acceleration lon,
  J29451Acceleration lat,
  J29451VerticalAcceleration vert,
  J29451YawRate yaw)
{
  Log(kJ29451LogLevel_Event,
      "Set user GNSS acceleration set 4 way - lon: %d(x0.01m/s^2), lat: %d(x0.01m/s^2), vert: %d(x0.02G), yaw: %d(x0.01degree/s)\n",
      lon, lat, vert, yaw);

  // 값의 범위를 조절한다.
  if (lon != kJ29451Acceleration_Unavailable) {
    lon = (lon < kJ29451Acceleration_Min) ? kJ29451Acceleration_Min : lon;
    lon = (lon > kJ29451Acceleration_Max) ? kJ29451Acceleration_Max : lon;
  }
  if (lat != kJ29451Acceleration_Unavailable) {
    lat = (lat < kJ29451Acceleration_Min) ? kJ29451Acceleration_Min : lat;
    lat = (lat > kJ29451Acceleration_Max) ? kJ29451Acceleration_Max : lat;
  }
  if (vert != kJ29451VerticalAcceleration_Unavailable) {
    vert = (vert < kJ29451VerticalAcceleration_Min) ? kJ29451VerticalAcceleration_Min : vert;
    vert = (vert > kJ29451VerticalAcceleration_Max) ? kJ29451VerticalAcceleration_Max : vert;
  }
  yaw = (yaw < kJ29451YawRate_Min) ? kJ29451YawRate_Min : yaw;
  yaw = (yaw > kJ29451YawRate_Max) ? kJ29451YawRate_Max : yaw;

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  struct J29451GNSSData *data = &(g_j29451_mib.obu.gnss.gnss_data);
  data->acceleration_set.lon = lon;
  data->acceleration_set.lat = lat;
  data->acceleration_set.vert = vert;
  data->acceleration_set.yaw = yaw;
  data->acceleration_set.lon_raw = j29451_ConvertToGNSSRawAcceleration(data->acceleration_set.lon);
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}
