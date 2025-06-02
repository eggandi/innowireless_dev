/** 
 * @file
 * @brief 차량상태정보를 설정하는 API를 구현한 파일
 * @date 2020-10-07
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 헤더 파일
#include "j29451/j29451-types.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-mib.h"
 

/**
 * @brief 차량 외부등 상태 정보를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] lights 설정할 외부등 상태 정보
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetVehicleExteriorLights(const struct J29451ExteriorLights *lights)
{
  Log(kJ29451LogLevel_Event, "Set vehicle exterior lights\n");

  // 파라미터 유효성을 체크한다.
  if (lights == NULL) {
    Err("Fail to set vehicle exterior lights - null parameters\n");
    return -kJ29451Result_InvalidParameters;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  memcpy(&(g_j29451_mib.vehicle.lights), lights, sizeof(struct J29451ExteriorLights));
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}


/**
 * @brief 저장되어 있는 차량 외부등 상태 정보를 해제한다(상세 내용은 API 매뉴얼 참조).
 */
void OPEN_API J29451_ClearVehicleExteriorLights(void)
{
  Log(kJ29451LogLevel_Event, "Clear vehicle exterior lights\n");

  pthread_mutex_lock(&(g_j29451_mib.mtx));
  memset(&(g_j29451_mib.vehicle.lights), 0, sizeof(struct J29451ExteriorLights));
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief 차량에 발생한 이벤트를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] event 설정할 이벤트 정보
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetVehicleEventFlags(const struct J29451VehicleEventFlags *event)
{
  Log(kJ29451LogLevel_Event, "Set vehicle event flags\n");

  // 파라미터 유효성을 체크한다.
  if (event == NULL) {
    Err("Fail to set vehicle event flags - null parameters\n");
    return -kJ29451Result_InvalidParameters;
  }

  // 값을 저장한다.
  bool event_set = event->hazard_lights || event->stop_line_violation || event->abs_activated ||
                   event->traction_control_loss || event->stability_control_activated || event->hazardous_materials ||
                   event->hard_braking || event->lights_changed || event->wiper_changed || event->flat_tire ||
                   event->disabled_vehicle || event->airbag_deployment;
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  memcpy(&(g_j29451_mib.vehicle.event.event), event, sizeof(struct J29451VehicleEventFlags));
  g_j29451_mib.vehicle.event.set = event_set; // 이벤트 플래그가 하나라도 set 되어 있는지 여부.
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}


/**
 * @brief 저장되어 있는 차량 이벤트 발생 정보를 해제한다(상세 내용은 API 매뉴얼 참조).
 */
void OPEN_API J29451_ClearVehicleEventFlags(void)
{
  Log(kJ29451LogLevel_Event, "Clear vehicle event flags\n");

  pthread_mutex_lock(&(g_j29451_mib.mtx));
  memset(&(g_j29451_mib.vehicle.event.event), 0, sizeof(struct J29451VehicleEventFlags));
  g_j29451_mib.vehicle.event.set = 0;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief 차량의 기어 상태를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] transmission 설정할 기어 상태
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetVehicleTransmissionState(J29451TransmissionState transmission)
{
  Log(kJ29451LogLevel_Event, "Set vehicle transmission state - %u\n", transmission);

  // 파라미터 유효성을 체크한다.
  if ((transmission != kJ29451TransmissionState_Unavailable) && (transmission > kJ29451TransmissionState_Max)) {
    Err("Fail to set vehicle transmission state - invalid state: %u\n", transmission);
    return -kJ29451Result_InvalidParameters;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.vehicle.transmission = transmission;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}


/**
 * @brief 차량의 속도를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] speed 설정할 속도
 */
void OPEN_API J29451_SetVehicleSpeed(J29451Speed speed)
{
  Log(kJ29451LogLevel_Event, "Set vehicle speed - %u(x0.02m/s)\n", speed);

  // 값의 범위를 조절한다.
  if (speed != kJ29451Speed_Unavailable) {
    speed = (speed > kJ29451Speed_Max) ? kJ29451Speed_Max : speed;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.vehicle.speed = speed;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief 차량의 스티어링 휠 각도를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] angle 설정할 각도
 */
void OPEN_API J29451_SetVehicleSteeringWheelAngle(J29451SteeringWheelAngle angle)
{
  Log(kJ29451LogLevel_Event, "Set vehicle steering wheel angle - %d(x1.5degrees)\n", angle);

  // 값의 범위를 조절한다.
  if (angle != kJ29451SteeringWheelAngle_Unavailable) {
    angle = (angle < kJ29451SteeringWheelAngle_Min) ? kJ29451SteeringWheelAngle_Min : angle;
    angle = (angle > kJ29451SteeringWheelAngle_Max) ? kJ29451SteeringWheelAngle_Max : angle;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.vehicle.angle = angle;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief 차량의 브레이크 적용 상태를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] brakes 설정할 브레이크 적용 상태 정보
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetVehicleBrakeAppliedStatus(const struct J29451BrakeAppliedStatus *brakes)
{
  Log(kJ29451LogLevel_Event, "Set vehicle brake applied status\n");

  // 파라미터 유효성을 체크한다.
  if (brakes == NULL) {
    Err("Fail to set vehicle brake applied status - null parameters\n");
    return -kJ29451Result_InvalidParameters;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  memcpy(&(g_j29451_mib.vehicle.brakes.wheel_brakes), brakes, sizeof(struct J29451BrakeAppliedStatus));
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}


/**
 * @brief 저장된 차량 브레이크 적용 상태를 해제한다(상세 내용은 API 매뉴얼 참조).
 */
void OPEN_API J29451_ClearVehicleBrakeAppliedStatus(void)
{
  Log(kJ29451LogLevel_Event, "Clear vehicle brake applied status\n");
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  memset(&(g_j29451_mib.vehicle.brakes.wheel_brakes), 0, sizeof(struct J29451BrakeAppliedStatus));
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
}


/**
 * @brief 차량의 traction control 상태를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] status 설정할 traction control 상태 정보
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetVehicleTractionControlStatus(J29451TractionControlStatus status)
{
  Log(kJ29451LogLevel_Event, "Set vehicle traction control statu - %u\n", status);

  // 파라미터 유효성을 체크한다.
  if (status > kJ29451TractionControlStatus_Max) {
    Err("Fail to set vehicle traction control status - invalid status: %u\n", status);
    return -kJ29451Result_InvalidParameters;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.vehicle.brakes.traction = status;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}


/**
 * @brief 차량의 anti lock brake 상태를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] status 설정할 anti lock brake 상태 정보
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetVehicleAntiLockBrakeStatus(J29451AntiLockBrakeStatus status)
{
  Log(kJ29451LogLevel_Event, "Set vehicle anti lock brake status - %u\n", status);

  // 파라미터 유효성을 체크한다.
  if (status > kJ29451AntiLockBrakeStatus_Max) {
    Err("Fail to set vehicle anti lock brake status - invalid status: %u\n", status);
    return -kJ29451Result_InvalidParameters;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.vehicle.brakes.abs = status;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}


/**
 * @brief 차량의 stability control 상태를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] status 설정할 stability control 상태 정보
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetVehicleStabilityControlStatus(J29451StabilityControlStatus status)
{
  Log(kJ29451LogLevel_Event, "Set vehicle stability control status - %u\n", status);

  // 파라미터 유효성을 체크한다.
  if (status > kJ29451StabilityControlStatus_Max) {
    Err("Fail to set vehicle stability control status - invalid status: %u\n", status);
    return -kJ29451Result_InvalidParameters;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.vehicle.brakes.scs = status;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}



/**
 * @brief 차량의 brake boost applied 상태를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] brake_boost 설정할 brake boost applied 상태 정보
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetVehicleBrakeBoostApplied(J29451BrakeBoostApplied brake_boost)
{
  Log(kJ29451LogLevel_Event, "Set vehicle brake boost applied - %u\n", brake_boost);

  // 파라미터 유효성을 체크한다.
  if (brake_boost > kJ29451BrakeBoostApplied_Max) {
    Err("Fail to set vehicle brake boost applied - invalid: %u\n", brake_boost);
    return -kJ29451Result_InvalidParameters;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.vehicle.brakes.brake_boost = brake_boost;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}


/**
 * @brief 차량의 보조 브레이크 상태를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] status 설정할 보조 브레이크 상태 정보
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetVehicleAuxiliaryBrakeStatus(J29451AuxiliaryBrakeStatus status)
{
  Log(kJ29451LogLevel_Event, "Set vehicle auxiliary brake status - %u\n", status);

  // 파라미터 유효성을 체크한다.
  if (status > kJ29451BrakeBoostApplied_Max) {
    Err("Fail to set vehicle auxiliary brake status - invalid status: %u\n", status);
    return -kJ29451Result_InvalidParameters;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.vehicle.brakes.aux_brakes = status;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}


/**
 * @brief 차량의 크기를 설정한다(상세 내용은 API 매뉴얼 참조).
 * @param[in] width 차량의 넓이
 * @param[in] length 차량의 길이
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int OPEN_API J29451_SetVehicleSize(J29451VehicleWidth width, J29451VehicleLength length)
{
  Log(kJ29451LogLevel_Event, "Set vehicle size - width: %ucm, length: %ucm\n", width, length);

  // 파라미터 유효성을 체크한다.
  if (width > kJ29451VehicleWidth_Max) {
    Err("Fail to set vehicle size - invalid width: %u\n", width);
    return -kJ29451Result_InvalidParameters;
  }
  if (length > kJ29451VehicleLength_Max) {
    Err("Fail to set vehicle size - invalid length: %u\n", length);
    return -kJ29451Result_InvalidParameters;
  }

  // 값을 저장한다.
  pthread_mutex_lock(&(g_j29451_mib.mtx));
  g_j29451_mib.vehicle.size.width = width;
  g_j29451_mib.vehicle.size.length = length;
  pthread_mutex_unlock(&(g_j29451_mib.mtx));
  return kJ29451Result_Success;
}

