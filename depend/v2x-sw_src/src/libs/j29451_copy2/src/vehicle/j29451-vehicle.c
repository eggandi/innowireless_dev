/** 
 * @file
 * @brief 차량정보 관련 기능 구현 파일
 * @date 2020-10-06
 * @author gyun
 */
 

// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"



/**
 * @brief 차량정보를 초기화한다.
 * @param[in] vehicle 차량정보
 */
void INTERNAL j29451_InitVehicleInfo(struct J29451VehicleInfo *vehicle)
{
  Log(kJ29451LogLevel_Event, "Initialize vehicle info\n");

  memset(vehicle, 0, sizeof(struct J29451VehicleInfo));
  vehicle->transmission = kJ29451TransmissionState_Unavailable;
  vehicle->speed = kJ29451Speed_Unavailable;
  vehicle->angle = kJ29451SteeringWheelAngle_Unavailable;
  vehicle->brakes.wheel_brakes.unavailable = true;
}


/**
 * @brief 차량정보를 해제한다.
 * @param[in] vehicle 차량정보
 */
void INTERNAL j29451_ReleaseVehicleInfo(struct J29451VehicleInfo *vehicle)
{
  Log(kJ29451LogLevel_Event, "Release vehicle info\n");
  j29451_InitVehicleInfo(vehicle);
}


/**
 * @brief 차량 정보가 BSM을 전송하기에 충분한지 확인한다.
 * @param[in] vehicle 차량정보
 * @retval true: BSM을 전송하기에 충분함
 * @retval false: BSM을 전송하기에 충분하지 않음
 *
 * SAE J2945/1 Table 19에 정의된 기준에 따라 판단한다.
 */
static bool j29451_CheckIfSufficientVehicleInfo(struct J29451VehicleInfo *vehicle)
{
  if ((vehicle->size.width == kJ29451VehicleWidth_Unavailable) ||
      (vehicle->size.length == kJ29451VehicleLength_Unavailable)) {
    Err("Insufficient vehicle info - vehicle size\n");
    return false;
  }
  return true;
}


/**
 * @brief 최신 차량정보를 획득한다.
 * @param[out] vehicle 차량정보가 저장될 구조체 변수 포인터
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int INTERNAL j29451_GetCurrentVehicleInfo(struct J29451VehicleInfo *vehicle)
{
  Log(kJ29451LogLevel_Event, "Get current vehicle info\n");

  memcpy(vehicle, &(g_j29451_mib.vehicle), sizeof(struct J29451VehicleInfo));

  /*
   * 차량정보가 BSM을 전송하기에 충분하지 않을 경우 실패를 반환한다.
   */
  if (j29451_CheckIfSufficientVehicleInfo(vehicle) == false) {
    return -kJ29451Result_InsufficientData;
  }
  return kJ29451Result_Success;
}
