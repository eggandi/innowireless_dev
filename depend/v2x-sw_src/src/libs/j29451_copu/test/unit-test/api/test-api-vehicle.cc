/** 
 * @file
 * @brief 차량상태정보 관련 API에 대한 단위테스트 구현 파일
 * @date 2020-10-07
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "j29451/j29451.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-mib.h"

// 단위테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-libj29451.h"


/*
 * J9451_SetVehicleExteriorLights()/J29451_ClearVehicleExteriorLights() API의 기본 동작 확인
 */
TEST(J9451_SetVehicleExteriorLights, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * API 호출 시 정보가 정상적으로 설정되는 것을 확인한다.
   */
  struct J29451ExteriorLights lights = { true, true, true, true, true, false, false, false, false };
  ASSERT_EQ(J29451_SetVehicleExteriorLights(&lights), kJ29451Result_Success);
  ASSERT_TRUE(g_j29451_mib.vehicle.lights.low_beam_headlight_on);
  ASSERT_TRUE(g_j29451_mib.vehicle.lights.high_beam_headlight_on);
  ASSERT_TRUE(g_j29451_mib.vehicle.lights.left_turn_signal_on);
  ASSERT_TRUE(g_j29451_mib.vehicle.lights.right_turn_signal_on);
  ASSERT_TRUE(g_j29451_mib.vehicle.lights.hazard_signal_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.automatic_light_control_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.daytime_running_lights_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.fog_light_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.parking_light_on);

  /*
   * 잘못된 파라미터 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleExteriorLights(nullptr), -kJ29451Result_InvalidParameters);

  /*
   * J29451_ClearVehicleExteriorLights() API 호출 시 설정되어 있던 정보가 정상적으로 해제되는 것을 확인한다.
   */
  J29451_ClearVehicleExteriorLights();
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.low_beam_headlight_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.high_beam_headlight_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.left_turn_signal_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.right_turn_signal_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.hazard_signal_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.automatic_light_control_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.daytime_running_lights_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.fog_light_on);
  ASSERT_FALSE(g_j29451_mib.vehicle.lights.parking_light_on);

  J29451Test_ReleaseEnv();
}


/*
 * J9451_SetVehicleExteriorLights()/J29451_ClearVehicleEventFlags() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleEventFlags, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * API 호출 시 정보가 정상적으로 설정되는 것을 확인한다.
   */
  struct J29451VehicleEventFlags event1 = { true, true, true, true, true, false, false, false, false, false, true, false, true };
  ASSERT_EQ(J29451_SetVehicleEventFlags(&event1), kJ29451Result_Success);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.hazard_lights);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.stop_line_violation);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.abs_activated);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.traction_control_loss);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.stability_control_activated);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.hazardous_materials);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.hard_braking);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.lights_changed);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.wiper_changed);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.flat_tire);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.disabled_vehicle);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.airbag_deployment);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.set);

  /*
   * API 호출 시 모든 정보가 clear 상태면 set 변수가 clear 되는 것을 확인한다.
   */
  struct J29451VehicleEventFlags event2 = { false, false, false, false, false, false, false, false, false, false, false, false, false };
  ASSERT_EQ(J29451_SetVehicleEventFlags(&event2), kJ29451Result_Success);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.hazard_lights);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.stop_line_violation);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.abs_activated);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.traction_control_loss);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.stability_control_activated);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.hazardous_materials);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.hard_braking);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.lights_changed);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.wiper_changed);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.flat_tire);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.disabled_vehicle);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.airbag_deployment);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.set);

  /*
   * API 호출 시 정보가 정상적으로 설정되는 것을 확인한다 - J29451_ClearVehicleEventFlags() API 테스트를 위해.
   */
  ASSERT_EQ(J29451_SetVehicleEventFlags(&event1), kJ29451Result_Success);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.hazard_lights);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.stop_line_violation);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.abs_activated);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.traction_control_loss);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.stability_control_activated);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.hazardous_materials);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.hard_braking);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.lights_changed);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.wiper_changed);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.flat_tire);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.disabled_vehicle);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.event.airbag_deployment);
  ASSERT_TRUE(g_j29451_mib.vehicle.event.set);

  /*
   * 잘못된 파라미터 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleEventFlags(nullptr), -kJ29451Result_InvalidParameters);

  /*
   * J29451_ClearVehicleExteriorLights() API 호출 시 설정되어 있던 정보가 정상적으로 해제되는 것을 확인한다.
   */
  J29451_ClearVehicleEventFlags();
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.hazard_lights);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.stop_line_violation);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.abs_activated);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.traction_control_loss);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.stability_control_activated);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.hazardous_materials);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.hard_braking);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.lights_changed);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.wiper_changed);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.flat_tire);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.disabled_vehicle);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.event.airbag_deployment);
  ASSERT_FALSE(g_j29451_mib.vehicle.event.set);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetVehicleTransmissionState() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleTransmissionState, NORMAL)
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
  ASSERT_EQ(J29451_SetVehicleTransmissionState(kJ29451TransmissionState_Neutral), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.transmission, kJ29451TransmissionState_Neutral);
  ASSERT_EQ(J29451_SetVehicleTransmissionState(kJ29451TransmissionState_Park), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.transmission, kJ29451TransmissionState_Park);
  ASSERT_EQ(J29451_SetVehicleTransmissionState(kJ29451TransmissionState_ForwardGears), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.transmission, kJ29451TransmissionState_ForwardGears);
  ASSERT_EQ(J29451_SetVehicleTransmissionState(kJ29451TransmissionState_ReverseGears), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.transmission, kJ29451TransmissionState_ReverseGears);
  ASSERT_EQ(J29451_SetVehicleTransmissionState(kJ29451TransmissionState_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.transmission, kJ29451TransmissionState_Unavailable);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleTransmissionState(kJ29451TransmissionState_Max + 1), -kJ29451Result_InvalidParameters);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetVehicleSpeed() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleSpeed, NORMAL)
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
  J29451_SetVehicleSpeed(kJ29451Speed_Min);
  ASSERT_EQ(g_j29451_mib.vehicle.speed, kJ29451Speed_Min);
  J29451_SetVehicleSpeed(kJ29451Speed_Max);
  ASSERT_EQ(g_j29451_mib.vehicle.speed, kJ29451Speed_Max);
  J29451_SetVehicleSpeed(kJ29451Speed_Unavailable);
  ASSERT_EQ(g_j29451_mib.vehicle.speed, kJ29451Speed_Unavailable);

  /*
   * 범위 밖의 값 전달 시, 경계값으로 조정되는 것을 확인한다.
   */
  J29451_SetVehicleSpeed(kJ29451Speed_Unavailable + 1);
  ASSERT_EQ(g_j29451_mib.vehicle.speed, kJ29451Speed_Max);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetVehicleSteeringWheelAngle() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleSteeringWheelAngle, NORMAL)
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
  J29451_SetVehicleSteeringWheelAngle(kJ29451SteeringWheelAngle_Min);
  ASSERT_EQ(g_j29451_mib.vehicle.angle, kJ29451SteeringWheelAngle_Min);
  J29451_SetVehicleSteeringWheelAngle(kJ29451SteeringWheelAngle_Max);
  ASSERT_EQ(g_j29451_mib.vehicle.angle, kJ29451SteeringWheelAngle_Max);
  J29451_SetVehicleSteeringWheelAngle(kJ29451SteeringWheelAngle_Unavailable);
  ASSERT_EQ(g_j29451_mib.vehicle.angle, kJ29451SteeringWheelAngle_Unavailable);

  /*
   * 범위 밖의 값 전달 시, 경계값으로 조정되는 것을 확인한다.
   */
  J29451_SetVehicleSteeringWheelAngle(kJ29451SteeringWheelAngle_Min - 1);
  ASSERT_EQ(g_j29451_mib.vehicle.angle, kJ29451SteeringWheelAngle_Min);
  J29451_SetVehicleSteeringWheelAngle(kJ29451SteeringWheelAngle_Unavailable + 1);
  ASSERT_EQ(g_j29451_mib.vehicle.angle, kJ29451SteeringWheelAngle_Max);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetVehicleBrakeAppliedStatus()/J29451_ClearVehicleBrakeAppliedStatus() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleBrakeAppliedStatus, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * API 호출 시 정보가 정상적으로 설정되는 것을 확인한다.
   */
  struct J29451BrakeAppliedStatus status = { true, false, true, true, false };
  ASSERT_EQ(J29451_SetVehicleBrakeAppliedStatus(&status), kJ29451Result_Success);
  ASSERT_TRUE(g_j29451_mib.vehicle.brakes.wheel_brakes.unavailable);
  ASSERT_FALSE(g_j29451_mib.vehicle.brakes.wheel_brakes.left_front);
  ASSERT_TRUE(g_j29451_mib.vehicle.brakes.wheel_brakes.left_rear);
  ASSERT_TRUE(g_j29451_mib.vehicle.brakes.wheel_brakes.right_front);
  ASSERT_FALSE(g_j29451_mib.vehicle.brakes.wheel_brakes.right_rear);

  /*
   * 잘못된 파라미터 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleBrakeAppliedStatus(nullptr), -kJ29451Result_InvalidParameters);

  /*
   * J29451_ClearVehicleBrakeAppliedStatus() API 호출 시 설정되어 있던 정보가 정상적으로 해제되는 것을 확인한다.
   */
  J29451_ClearVehicleBrakeAppliedStatus();
  ASSERT_FALSE(g_j29451_mib.vehicle.brakes.wheel_brakes.unavailable);
  ASSERT_FALSE(g_j29451_mib.vehicle.brakes.wheel_brakes.left_front);
  ASSERT_FALSE(g_j29451_mib.vehicle.brakes.wheel_brakes.left_rear);
  ASSERT_FALSE(g_j29451_mib.vehicle.brakes.wheel_brakes.right_front);
  ASSERT_FALSE(g_j29451_mib.vehicle.brakes.wheel_brakes.right_rear);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetVehicleTractionControlStatus() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleTractionControlStatus, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * API 호출 시 정보가 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleTractionControlStatus(kJ29451TractionControlStatus_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.traction, kJ29451TractionControlStatus_Unavailable);
  ASSERT_EQ(J29451_SetVehicleTractionControlStatus(kJ29451TractionControlStatus_Off), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.traction, kJ29451TractionControlStatus_Off);
  ASSERT_EQ(J29451_SetVehicleTractionControlStatus(kJ29451TractionControlStatus_On), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.traction, kJ29451TractionControlStatus_On);
  ASSERT_EQ(J29451_SetVehicleTractionControlStatus(kJ29451TractionControlStatus_Engaged), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.traction, kJ29451TractionControlStatus_Engaged);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleTractionControlStatus(kJ29451TractionControlStatus_Max + 1), -kJ29451Result_InvalidParameters);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetVehicleAntiLockBrakeStatus() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleAntiLockBrakeStatus, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * API 호출 시 정보가 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleAntiLockBrakeStatus(kJ29451AntiLockBrakeStatus_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.abs, kJ29451AntiLockBrakeStatus_Unavailable);
  ASSERT_EQ(J29451_SetVehicleAntiLockBrakeStatus(kJ29451AntiLockBrakeStatus_Off), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.abs, kJ29451AntiLockBrakeStatus_Off);
  ASSERT_EQ(J29451_SetVehicleAntiLockBrakeStatus(kJ29451AntiLockBrakeStatus_On), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.abs, kJ29451AntiLockBrakeStatus_On);
  ASSERT_EQ(J29451_SetVehicleAntiLockBrakeStatus(kJ29451AntiLockBrakeStatus_Engaged), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.abs, kJ29451AntiLockBrakeStatus_Engaged);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleAntiLockBrakeStatus(kJ29451AntiLockBrakeStatus_Max + 1), -kJ29451Result_InvalidParameters);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetVehicleStabilityControlStatus() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleStabilityControlStatus, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * API 호출 시 정보가 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleStabilityControlStatus(kJ29451StabilityControlStatus_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.scs, kJ29451StabilityControlStatus_Unavailable);
  ASSERT_EQ(J29451_SetVehicleStabilityControlStatus(kJ29451StabilityControlStatus_Off), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.scs, kJ29451StabilityControlStatus_Off);
  ASSERT_EQ(J29451_SetVehicleStabilityControlStatus(kJ29451StabilityControlStatus_On), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.scs, kJ29451StabilityControlStatus_On);
  ASSERT_EQ(J29451_SetVehicleStabilityControlStatus(kJ29451StabilityControlStatus_Engaged), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.scs, kJ29451StabilityControlStatus_Engaged);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleStabilityControlStatus(kJ29451StabilityControlStatus_Max + 1), -kJ29451Result_InvalidParameters);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetVehicleBrakeBoostApplied() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleBrakeBoostApplied, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * API 호출 시 정보가 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleBrakeBoostApplied(kJ29451BrakeBoostApplied_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.brake_boost, kJ29451BrakeBoostApplied_Unavailable);
  ASSERT_EQ(J29451_SetVehicleBrakeBoostApplied(kJ29451BrakeBoostApplied_Off), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.brake_boost, kJ29451BrakeBoostApplied_Off);
  ASSERT_EQ(J29451_SetVehicleBrakeBoostApplied(kJ29451BrakeBoostApplied_On), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.brake_boost, kJ29451BrakeBoostApplied_On);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleBrakeBoostApplied(kJ29451BrakeBoostApplied_Max + 1), -kJ29451Result_InvalidParameters);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetVehicleAuxiliaryBrakeStatus() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleAuxiliaryBrakeStatus, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * API 호출 시 정보가 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleAuxiliaryBrakeStatus(kJ29451AuxiliaryBrakeStatus_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.aux_brakes, kJ29451AuxiliaryBrakeStatus_Unavailable);
  ASSERT_EQ(J29451_SetVehicleAuxiliaryBrakeStatus(kJ29451AuxiliaryBrakeStatus_Off), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.aux_brakes, kJ29451AuxiliaryBrakeStatus_Off);
  ASSERT_EQ(J29451_SetVehicleAuxiliaryBrakeStatus(kJ29451AuxiliaryBrakeStatus_On), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.brakes.aux_brakes, kJ29451AuxiliaryBrakeStatus_On);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleAuxiliaryBrakeStatus(kJ29451AuxiliaryBrakeStatus_Max + 1), -kJ29451Result_InvalidParameters);

  J29451Test_ReleaseEnv();
}


/*
 * J29451_SetVehicleSize() API의 기본 동작 확인
 */
TEST(J29451_SetVehicleSize, NORMAL)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * API 호출 시 정보가 정상적으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleSize(kJ29451VehicleWidth_Min, kJ29451VehicleLength_Min), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.size.width, kJ29451VehicleWidth_Min);
  ASSERT_EQ(g_j29451_mib.vehicle.size.length, kJ29451VehicleLength_Min);
  ASSERT_EQ(J29451_SetVehicleSize(kJ29451VehicleWidth_Max, kJ29451VehicleLength_Max), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.size.width, kJ29451VehicleWidth_Max);
  ASSERT_EQ(g_j29451_mib.vehicle.size.length, kJ29451VehicleLength_Max);
  ASSERT_EQ(J29451_SetVehicleSize(kJ29451VehicleWidth_Unavailable, kJ29451VehicleLength_Unavailable), kJ29451Result_Success);
  ASSERT_EQ(g_j29451_mib.vehicle.size.width, kJ29451VehicleWidth_Unavailable);
  ASSERT_EQ(g_j29451_mib.vehicle.size.length, kJ29451VehicleLength_Unavailable);

  /*
   * 유효하지 않은 값 전달 시, 정상적으로 예외 처리하는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetVehicleSize(kJ29451VehicleWidth_Max + 1, kJ29451VehicleLength_Max), -kJ29451Result_InvalidParameters);
  ASSERT_EQ(J29451_SetVehicleSize(kJ29451VehicleWidth_Max, kJ29451VehicleLength_Max + 1), -kJ29451Result_InvalidParameters);

  J29451Test_ReleaseEnv();
}
