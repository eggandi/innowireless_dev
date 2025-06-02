/** 
  * @file 
  * @brief 단위테스트 관련 기능 (단위테스트 수행시에만 사용된다)
  * @date 2022-09-16 
  * @author gyun 
  */

#ifndef V2X_SW_J29451_TEST_H
#define V2X_SW_J29451_TEST_H

#ifdef _UNIT_TEST_


// 시스템 헤더 파일
#include <time.h>


#define TEST_GNSS_DATA_NUM (500) ///< 테스트용 GPS 데이터 개수
#define TEST_GNSS_DATA_INITIAL_LAT_RAW (37.406526) ///< 초기값 (1도 단위)
#define TEST_GNSS_DATA_INITIAL_LON_RAW (127.102395) ///< 초기값 (1도 단위)
#define TEST_GNSS_DATA_INITIAL_ELEV_RAW (0.0) ///< 초기값 (1미터 단위)
#define TEST_GNSS_DATA_INITIAL_SPEED_RAW (30.0) ///< 초기값 (1m/s 단위)
#define TEST_GNSS_DATA_INITIAL_HEADING_RAW (1.0) ///< 초기값 (1도 단위)
#define TEST_GNSS_DATA_INITIAL_SEMI_MAJOR_AXIS_ACCURACY_RAW (0.0) ///< 초기값 (1미터 단위)
#define TEST_GNSS_DATA_INITIAL_SEMI_MINOR_AXIS_ACCURACY_RAW (0.1) ///< 초기값 (1미터 단위)
#define TEST_GNSS_DATA_INITIAL_SEMI_MAJOR_AXIS_ORIENTATION_RAW (0.1) ///< 초기값 (1도 단위)
#define TEST_GNSS_DATA_INITIAL_LAT_ACCELERATION_RAW (0.1) ///< 초기값 1m/s^2 단위
#define TEST_GNSS_DATA_INITIAL_LON_ACCELERATION_RAW (0.1) ///< 초기값 1m/s^2 단위
#define TEST_GNSS_DATA_INITIAL_VERT_ACCELERATION_RAW (0.1) ///< 초기값 1m/s^2 단위
#define TEST_GNSS_DATA_INITIAL_YAW_RATE_RAW (0.1) ///< 초기값 1도/s 단위
#define TEST_GNSS_DATA_INITIAL_LAT (374065260) ///< 초기값
#define TEST_GNSS_DATA_INITIAL_LON (1271023950) ///< 초기값
#define TEST_GNSS_DATA_INITIAL_ELEV (0) ///< 초기값
#define TEST_GNSS_DATA_INITIAL_SPEED (1500) ///< 초기값
#define TEST_GNSS_DATA_INITIAL_HEADING (0) ///< 초기값
#define TEST_GNSS_DATA_INITIAL_SEMI_MAJOR_AXIS_ACCURACY (1) ///< 초기값 (0.05미터 단위)
#define TEST_GNSS_DATA_INITIAL_SEMI_MINOR_AXIS_ACCURACY (2) ///< 초기값 (0.05미터 단위)
#define TEST_GNSS_DATA_INITIAL_SEMI_MAJOR_AXIS_ORIENTATION (3) ///< 초기값 (360/65535 = 0.0054932479 도 단위)
#define TEST_GNSS_DATA_INITIAL_LAT_ACCELERATION (4) ///< 초기값 (0.01m/s^2 단위)
#define TEST_GNSS_DATA_INITIAL_LON_ACCELERATION (5) ///< 초기값 (0.01m/s^2 단위)
#define TEST_GNSS_DATA_INITIAL_VERT_ACCELERATION (6) ///< 초기값 (0.02G 단위 = 0.1962 m/s^2)
#define TEST_GNSS_DATA_INITIAL_YAW_RATE (7) ///< 초기값 (0.01 도/s 단위)
#define TEST_VEHICLE_INFO_INITIAL_WIDTH (150) ///< 초기값
#define TEST_VEHICLE_INFO_INITIAL_LENGTH (300) ///< 초기값
#define LAT_RAW_OFFSET (0.000017) ///< 위도 오프셋 (1도 단위)
#define LON_RAW_OFFSET (0.000028) ///< 경도 오프셋 (1도 단위)
#define ELEV_RAW_OFFSET (0.1) ///< 고도 오프셋 (1미터 단위). 2735에 정의된 단위값(0.1미터)씩 증가
#define SPEED_RAW_OFFSET (0.02) ///< 속도 오프셋 (1m/s 단위). 2735에 정의된 단위값(0.02m/s)씩 증가
#define HEADING_RAW_OFFSET (0.0125) ///< heading 오프셋 (1도 단위). 2735에 정의된 단위값(0.0125도)씩 증가


/**
 * 단위테스트 시에 사용되는 gps_data 형식 - gpsd의 gps_data_t 구조체 모사(사용되는 항목만)
 */
struct J29451TestGPSData
{
  struct {
#define MODE_NOT_SEEN	0	/* mode update not seen yet */
#define MODE_NO_FIX	1	/* none */
#define MODE_2D  	2	/* good for latitude/longitude */
#define MODE_3D  	3	/* good for altitude/climb too */
    int mode;
    double latitude; ///< 1도 단위 위도
    double longitude; ///< 1도 단위 경도
    double speed; ///< 1m/s 단위 속도
    double track; ///< 1도 단위 방향
    double altHAE; ///< 1미터 단위 고도
    struct timespec time; ///< 정보획득 시각
  } fix;
  struct {
    double smajor_deviation; ///< 1미터 단위
    double sminor_deviation; ///< 1미터 단위
    double smajor_orientation; ///< 1도 단위
  } gst;
  struct {
    double acc_x; ///< 1m/s^2 단위. longitudinal acceleration (종방향 가속도)
    double acc_y; ///< 1m/s^2 단위. lateral acceleration (횡방향 가속도)
    double acc_z; ///< 1m/s^2 단위. vertical acceleration
    double gyro_z; ///< 1도/s 단위. yaw rate (gps.h 파일에는 이 변수가 1도/s^2으로 표시되어 있으나, 우리는 1도/s로 사용한다)
  } attitude;
};

extern int g_test_gps_data_idx;
extern struct J29451TestGPSData g_test_gps_data[];

#endif // _UNIT_TEST_

#endif //V2X_SW_J29451_TEST_H
