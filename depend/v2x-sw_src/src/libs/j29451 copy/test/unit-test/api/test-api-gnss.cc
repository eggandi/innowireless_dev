/** 
 * @file
 * @brief GNSS 정보 관련 API에 대한 단위테스트 구현 파일
 * @date 2020-10-09
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "j29451/j29451.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"

// 단위테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-libj29451.h"


/*
 * J29451_EnableUserGNSSData()/J29451_DisableUserGNSSData() API의 기본 동작 확인
 */
TEST(J29451_EnableUserGNSSData, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 초기 기본값을 확인한다.
   */
  ASSERT_FALSE(g_j29451_mib.obu.gnss.user_gnss_enable);

  /*
   * API 호출 시 정상적으로 설정되는 것을 확인한다.
   */
  J29451_EnableUserGNSSData();
  ASSERT_TRUE(g_j29451_mib.obu.gnss.user_gnss_enable);

  J29451_DisableUserGNSSData();
  ASSERT_FALSE(g_j29451_mib.obu.gnss.user_gnss_enable);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetUserGNSSLatitude() API의 기본 동작 확인
 */
TEST(J29451_SetUserGNSSLatitude, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 사용자 GNSS 입력을 활성화한다.
   */
  J29451_EnableUserGNSSData();

  /*
   * 유효한 값 전달 시, 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLatitude(kJ29451Latitude_Min), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.lat, kJ29451Latitude_Min);
  ASSERT_EQ(J29451_SetUserGNSSLatitude(kJ29451Latitude_Max), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.lat, kJ29451Latitude_Max);
  ASSERT_EQ(J29451_SetUserGNSSLatitude(kJ29451Latitude_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.lat, kJ29451Latitude_Unavailable);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLatitude(kJ29451Latitude_Min - 1), -kJ29451Result_InvalidParameters);
  ASSERT_EQ(J29451_SetUserGNSSLatitude(kJ29451Latitude_Unavailable + 1), -kJ29451Result_InvalidParameters);

  /*
   * 사용자 GNSS 입력 비활성화 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  J29451_DisableUserGNSSData();
  ASSERT_EQ(J29451_SetUserGNSSLatitude(kJ29451Latitude_Min), -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSLatitude(kJ29451Latitude_Max), -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSLatitude(kJ29451Latitude_Unavailable), -kJ29451Result_UserGNSSDataNotAllowed);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetUserGNSSLongitude() API의 기본 동작 확인
 */
TEST(J29451_SetUserGNSSLongitude, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 사용자 GNSS 입력을 활성화한다.
   */
  J29451_EnableUserGNSSData();

  /*
   * 유효한 값 전달 시, 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLongitude(kJ29451Longitude_Min), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.lon, kJ29451Longitude_Min);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(kJ29451Longitude_Max), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.lon, kJ29451Longitude_Max);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(kJ29451Longitude_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.lon, kJ29451Longitude_Unavailable);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLongitude(kJ29451Longitude_Min - 1), -kJ29451Result_InvalidParameters);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(kJ29451Longitude_Unavailable + 1), -kJ29451Result_InvalidParameters);

  /*
   * 사용자 GNSS 입력 비활성화 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  J29451_DisableUserGNSSData();
  ASSERT_EQ(J29451_SetUserGNSSLongitude(kJ29451Longitude_Min), -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(kJ29451Longitude_Max), -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(kJ29451Longitude_Unavailable), -kJ29451Result_UserGNSSDataNotAllowed);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetUserGNSSElevation() API의 기본 동작 확인
 */
TEST(J29451_SetUserGNSSElevation, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 사용자 GNSS 입력을 활성화한다.
   */
  J29451_EnableUserGNSSData();

  /*
   * 유효한 값 전달 시, 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSElevation(kJ29451Elevation_Min), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.elev, kJ29451Elevation_Min);
  ASSERT_EQ(J29451_SetUserGNSSElevation(kJ29451Elevation_Max), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.elev, kJ29451Elevation_Max);
  ASSERT_EQ(J29451_SetUserGNSSElevation(kJ29451Elevation_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.elev, kJ29451Elevation_Unavailable);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSElevation(kJ29451Elevation_Unavailable - 1), -kJ29451Result_InvalidParameters);
  ASSERT_EQ(J29451_SetUserGNSSElevation(kJ29451Elevation_Max + 1), -kJ29451Result_InvalidParameters);

  /*
   * 사용자 GNSS 입력 비활성화 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  J29451_DisableUserGNSSData();
  ASSERT_EQ(J29451_SetUserGNSSElevation(kJ29451Elevation_Min), -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSElevation(kJ29451Elevation_Max), -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSElevation(kJ29451Elevation_Unavailable), -kJ29451Result_UserGNSSDataNotAllowed);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetUserGNSSSpeed() API의 기본 동작 확인
 */
TEST(J29451_SetUserGNSSSpeed, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 사용자 GNSS 입력을 활성화한다.
   */
  J29451_EnableUserGNSSData();

  /*
   * 유효한 값 전달 시, 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSSpeed(kJ29451Speed_Min), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.speed, kJ29451Speed_Min);
  ASSERT_EQ(J29451_SetUserGNSSSpeed(kJ29451Speed_Max), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.speed, kJ29451Speed_Max);
  ASSERT_EQ(J29451_SetUserGNSSSpeed(kJ29451Speed_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.speed, kJ29451Speed_Unavailable);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSSpeed(kJ29451Speed_Unavailable + 1), -kJ29451Result_InvalidParameters);

  /*
   * 사용자 GNSS 입력 비활성화 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  J29451_DisableUserGNSSData();
  ASSERT_EQ(J29451_SetUserGNSSSpeed(kJ29451Speed_Min), -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSSpeed(kJ29451Speed_Max), -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSSpeed(kJ29451Speed_Unavailable), -kJ29451Result_UserGNSSDataNotAllowed);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetUserGNSSHeading() API의 기본 동작 확인
 */
TEST(J29451_SetUserGNSSHeading, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 사용자 GNSS 입력을 활성화한다.
   */
  J29451_EnableUserGNSSData();

  /*
   * 유효한 값 전달 시, 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSHeading(kJ29451Heading_Min), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.heading, kJ29451Heading_Min);
  ASSERT_EQ(J29451_SetUserGNSSHeading(kJ29451Heading_Max), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.heading, kJ29451Heading_Max);
  ASSERT_EQ(J29451_SetUserGNSSHeading(kJ29451Heading_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.heading, kJ29451Heading_Unavailable);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSHeading(kJ29451Heading_Unavailable + 1), -kJ29451Result_InvalidParameters);

  /*
   * 사용자 GNSS 입력 비활성화 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  J29451_DisableUserGNSSData();
  ASSERT_EQ(J29451_SetUserGNSSHeading(kJ29451Heading_Min), -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSHeading(kJ29451Heading_Max), -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSHeading(kJ29451Heading_Unavailable), -kJ29451Result_UserGNSSDataNotAllowed);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetUserGNSSPositionalAccuracy() API의 기본 동작 확인
 */
TEST(J29451_SetUserGNSSPositionalAccuracy, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 사용자 GNSS 입력을 활성화한다.
   */
  J29451_EnableUserGNSSData();

  /*
   * 유효한 값 전달 시, 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Min,
                                                 kJ29451SemiMinorAxisAccuracy_Min,
                                                 kJ29451SemiMajorAxisOrientation_Min), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_major, kJ29451SemiMajorAxisAccuracy_Min);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_minor, kJ29451SemiMinorAxisAccuracy_Min);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.orientation, kJ29451SemiMajorAxisOrientation_Min);
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Max,
                                                 kJ29451SemiMinorAxisAccuracy_Max,
                                                 kJ29451SemiMajorAxisOrientation_Max), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_major, kJ29451SemiMajorAxisAccuracy_Max);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_minor, kJ29451SemiMinorAxisAccuracy_Max);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.orientation, kJ29451SemiMajorAxisOrientation_Max);
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Unavailable,
                                                 kJ29451SemiMinorAxisAccuracy_Unavailable,
                                                 kJ29451SemiMajorAxisOrientation_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_major, kJ29451SemiMajorAxisAccuracy_Unavailable);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.semi_minor, kJ29451SemiMinorAxisAccuracy_Unavailable);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.pos_accuracy.orientation, kJ29451SemiMajorAxisOrientation_Unavailable);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Unavailable + 1,
                                                 kJ29451SemiMinorAxisAccuracy_Min,
                                                 kJ29451SemiMajorAxisOrientation_Min), -kJ29451Result_InvalidParameters);
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Min,
                                                 kJ29451SemiMinorAxisAccuracy_Unavailable + 1,
                                                 kJ29451SemiMajorAxisOrientation_Min), -kJ29451Result_InvalidParameters);
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Min,
                                                 kJ29451SemiMinorAxisAccuracy_Min,
                                                 kJ29451SemiMajorAxisOrientation_Unavailable + 1),
            -kJ29451Result_InvalidParameters);

  /*
   * 사용자 GNSS 입력 비활성화 시, 정상적으로 예외처리하는 것을 확인한다.
   */
  J29451_DisableUserGNSSData();
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Min,
                                                 kJ29451SemiMinorAxisAccuracy_Min,
                                                 kJ29451SemiMajorAxisOrientation_Min),
            -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Max,
                                                 kJ29451SemiMinorAxisAccuracy_Max,
                                                 kJ29451SemiMajorAxisOrientation_Max),
            -kJ29451Result_UserGNSSDataNotAllowed);
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Unavailable,
                                                 kJ29451SemiMinorAxisAccuracy_Unavailable,
                                                 kJ29451SemiMajorAxisOrientation_Unavailable),
            -kJ29451Result_UserGNSSDataNotAllowed);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetUserGNSSAccelerationSet4Way() API의 기본 동작 확인
 */
TEST(J29451_SetUserGNSSAccelerationSet4Way, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 유효한 값 전달 시 정상적으로 설정되는 것을 확인한다.
   */
  J29451_SetUserGNSSAccelerationSet4Way(kJ29451Acceleration_Min,
                                        kJ29451Acceleration_Min,
                                        kJ29451VerticalAcceleration_Min,
                                        kJ29451YawRate_Min);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lon, kJ29451Acceleration_Min);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lat, kJ29451Acceleration_Min);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.vert, kJ29451VerticalAcceleration_Min);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.yaw, kJ29451YawRate_Min);
  J29451_SetUserGNSSAccelerationSet4Way(kJ29451Acceleration_Max,
                                        kJ29451Acceleration_Max,
                                        kJ29451VerticalAcceleration_Max,
                                        kJ29451YawRate_Max);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lon, kJ29451Acceleration_Max);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lat, kJ29451Acceleration_Max);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.vert, kJ29451VerticalAcceleration_Max);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.yaw, kJ29451YawRate_Max);
  J29451_SetUserGNSSAccelerationSet4Way(kJ29451Acceleration_Unavailable,
                                        kJ29451Acceleration_Unavailable,
                                        kJ29451VerticalAcceleration_Unavailable,
                                        kJ29451YawRate_Max); // Yawrate는 Unavailable 값이 사용되지 않는다.
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lon, kJ29451Acceleration_Unavailable);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lat, kJ29451Acceleration_Unavailable);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.vert, kJ29451VerticalAcceleration_Unavailable);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.yaw, kJ29451YawRate_Max); // Yawrate는 Unavailable 값이 사용되지 않는다.

  /*
   * 범위 밖의 값 전달 시, 경계값으로 조정되는 것을 확인한다.
   */
  J29451_SetUserGNSSAccelerationSet4Way(kJ29451Acceleration_Min - 1,
                                        kJ29451Acceleration_Min - 1,
                                        kJ29451VerticalAcceleration_Min - 2,
                                        kJ29451YawRate_Min - 1);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lon, kJ29451Acceleration_Min);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lat, kJ29451Acceleration_Min);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.vert, kJ29451VerticalAcceleration_Min);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.yaw, kJ29451YawRate_Min);
  J29451_SetUserGNSSAccelerationSet4Way(kJ29451Acceleration_Unavailable + 1,
                                        kJ29451Acceleration_Unavailable + 1,
                                        kJ29451VerticalAcceleration_Max + 1,
                                        kJ29451YawRate_Max + 1);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lon, kJ29451Acceleration_Max);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.lat, kJ29451Acceleration_Max);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.vert, kJ29451VerticalAcceleration_Max);
  ASSERT_EQ(g_j29451_mib.obu.gnss.gnss_data.acceleration_set.yaw, kJ29451YawRate_Max);

  J29451Test_ReleaseEnv();
}

