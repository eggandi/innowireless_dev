/** 
 * @file
 * @brief BSM 생성 관련 기능을 구현한 파일
 * @date 2020-10-03
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdint.h>
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#if defined(_FFASN1C_)
#include "j29451-ffasn1c.h"
#elif defined(_OBJASN1C_)
#include "j29451-objasn1c.h"
#else
#error "3rd party asn.1 library is not defined"
#endif

/**
 * @brief BSM을 생성한다.
 * @param[in] gnss 현 시점의 GNSS 데이터
 * @param[in] vehicle 현 시점의 차량정보
 * @param[out] bsm_size 생성된 BSM의 길이가 반환될 변수 포인터
 * @return 생성된 BSM 바이트열 (호출자는 사용 후 free() 해 주어야 한다)
 * @retval NULL: 생성 실패
 */
uint8_t INTERNAL * j29451_ConstructBSM(struct J29451GNSSData *gnss, struct J29451VehicleInfo *vehicle, size_t *bsm_size)
{
#if defined(_FFASN1C_)
  return j29451_ffasn1c_ConstructBSM(gnss, vehicle, bsm_size);
#elif defined(_OBJASN1C_)
  return j29451_objasn1c_ConstructBSM(gnss, vehicle, bsm_size);
#else
#error "3rd party asn.1 library is not defined"
#endif
}
