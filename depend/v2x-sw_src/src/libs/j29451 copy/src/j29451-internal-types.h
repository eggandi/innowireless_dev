/** 
 * @file
 * @brief j29451 라이브러리 내부에서 사용되는 유형들을 정의한 헤더 파일
 * @date 2020-10-03
 * @author gyun
 */


#ifndef V2X_SW_J29451_INTERNAL_TYPES_H
#define V2X_SW_J29451_INTERNAL_TYPES_H


// 시스템 헤더 파일
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

// 라이브러리 헤더 파일
#include "j29451/j29451-types.h"


/**
 * @brief ID 변경 주기 (밀리초 단위)
 */
enum eJ29451IDChangeInterval
{
  kJ29451IDChangeInterval_Min = (0),
  kJ29451IDChangeInterval_Default = (5 * 60 * 1000), ///< J2945/1 규격에 정의된 기본값
};
typedef uint64_t J29451IDChangeInterval; ///< @ref eJ29451IDChangeInterval


/**
 * @brief ID 변경 거리 (미터 단위)
 */
enum eJ29451IDChangeDistance
{
  kJ29451IDChangeDistance_Min = (0),
  kJ29451IDChangeDistance_Default = (2 * 1000), ///< J2945/1 규격에 정의된 기본값
};
typedef double J29451IDChangeDistance; ///< @ref eJ29451IDChangeDistance


/**
 * @brief 위도/경도의 오프셋 (0.1 마이크로도 단위)
 */
enum eJ29451LatLonOffsetLL_B18
{
  kJ29451LatLonOffsetLL_B18_Min = -131071,
  kJ29451LatLonOffsetLL_B18_Max = 131071,
  kJ29451LatLonOffsetLL_B18_Unavailable = -131072,
};
typedef int J29451LatLonOffsetLL_B18; ///< @ref eJ29451LatLonOffsetLL_B18


/**
 * @brief z축 방향 오프셋 (0.1 미터 단위)
 */
enum eJ29451VertOffset_B12
{
  kJ29451VertOffset_B12_Min = -2047,
  kJ29451VertOffset_B12_Max = 2047,
  kJ29451VertOffset_B12_Unavailable = -2048,
};
typedef int J29451VertOffset_B12; ///< @ref eJ29451VertOffset_B12


/*
 * @brief 시간 오프셋 (10 millisecond 단위)
 */
enum eJ29451TimeOffset
{
  kJ29451TimeOffset_Min = 1,
  kJ29451TimeOffset_Max = 65534, ///< 10분 55.34초
  kJ29451TimeOffset_Unavailable = 65535,
};
typedef unsigned int J29451TimeOffset; ///< @ref eJ29451TimeOffset


/**
 * @brief 1분 내에서의 밀리초 표현 (1msec 단위)
 */
enum eJ29451DSecond
{
  kJ29451DSecond_Min = 0,
  kJ29451DSecond_Max = 60999,
  kJ29451DSecond_Unavailable = 65535,
};
typedef unsigned int J29451DSecond; ///< @ref eJ29451DSecond


/**
 * @brief GNSS 데이터 선택모드
 */
enum eJ29451GNSSDataSelectionMode
{
  /// GNSS 데이터 선택모드가 아직 설정되지 않은 상태
  kJ29451GNSSDataSelectionMode_Undef,

  /// 최근 업데이트된 GNSS 데이터 선택 모드
  /// GNSS 데이터 처리 타이머 만기 시점이 "필수 GNSS 데이터 업데이트 구간" 밖에 있는 경우의 동작 모드
  /// 이 경우, GNSS 데이터 처리 시점에 필수 GNSS 데이터가 업데이트 완료되었음을 확신할 수 있으므로, 최근 정보를 선택하여 처리한다.
  kJ29451GNSSDataSelectionMode_Recent,

  /// 안전한 GNSS 데이터 선택 모드
  /// GNSS 데이터 처리 타이머 만기 시점이 "필수 GNSS 데이터 업데이트 구간" 내에 있는 경우의 동작 모드
  /// 이 경우, GNSS 데이터 처리 시점에 필수 GNSS 데이터가 업데이트 완료되었음을 확신할 수 없으므로,
  /// 안전한(필수 GNSS 데이터 업데이트가 완료된) 정보를 선택하여 처리한다.
  kJ29451GNSSDataSelectionMode_Safe
};
typedef unsigned int J29451GNSSDataSelectionMode; ///< @ref eJ29451GNSSDataSelectionMode


/**
 * @brief Curvature(=RadiusOfCurvature의 역수) (1/m 단위)
 * 양수: 시계방향 회전
 * 음수: 시계반대방향 회전
 */
typedef double J29451Curvature;


/**
 * @brief GNSS 데이터
 */
struct J29451GNSSData
{
  int mode; ///< gps_data_t 구조체의 fix.mode 값이 저장됨
  int status; ///< gps_data_t 구조체의 fix.status 값이 저장됨
  uint64_t time; ///< GNSS 데이터가 획득된 시점의 리눅스시간 (밀리초단위) (=epoch time) (GPS모듈로부터 획득한 값이므로 시스템시간의 변경과 무관)
  J29451DSecond msec; ///< GNSS 데이터가 획득된 시점 (msec in minute). 위 time 변수값으로부터 계산된다.
  J29451Latitude lat; ///< 위도
  J29451Longitude lon; ///< 경도
  J29451Elevation elev; ///< 고도
  J29451Speed speed; ///< 속도
  J29451Heading heading; ///< 헤딩 (true north)
  struct {
    J29451SemiMajorAxisAccuracy semi_major; ///< semi-major axis accuracy
    J29451SemiMinorAxisAccuracy semi_minor; ///< semi-minor axis accuracy
    J29451SemiMajorAxisOrientation orientation; ///< semi-major asix orientation
  } pos_accuracy; ///< 좌표 정확성
  struct {
    J29451Acceleration lon; ///< 종방향 가속도
    J29451Acceleration lat; ///< 횡방향 가속도
    J29451VerticalAcceleration vert; // 수직방향 가속도
    J29451YawRate yaw; ///< yaw rate
    double lon_raw; ///< 종방향 가속도 (1m/s^2 단위 = gpsd 입력단위)
  } acceleration_set; ///< 가속도 정보
  double lat_deg; ///< GNSS 입력 위도 (1도 단위)
  double lon_deg; ///< GNSS 입력 경도 (1도 단위)
  double lat_rad; ///< 위도(라디안)
  double lon_rad; ///< 경도(라디안)
};


#endif //V2X_SW_J29451_INTERNAL_TYPES_H
