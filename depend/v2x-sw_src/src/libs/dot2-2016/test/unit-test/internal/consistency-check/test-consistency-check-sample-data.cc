/** 
  * @file 
  * @brief SPDU consistency check 단위테스트에 사용되는 샘플 데이터를 정의한 파일
  * @date 2021-09-06 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <cstring>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"
#include "v2x-sw.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "certificate/cert-info/dot2-cert-info.h"
#include "certificate/cert-info/dot2-ee-cert-cache.h"

// google test 헤더 파일
#include "test-consistency-check-sample-data.h"


/**
 * @brief 정상적인 SPDU 패킷파싱데이터를 설정한다.
 * @param[out] parsed 설정할 패킷파싱데이터
 *
 * 다음과 같이 정상 데이터가 설정된다.
 *  1. SPDU 생성시각 < SPDU 만기시각
 *  2. 인증서 유효기간 시작시점 < SPDU 생성시각 < SPDU 만기시각 < 인증서 유효기간 종료시점
 *  3. SPDU 생성좌표: SPDU 유효지역 내 지점 (원형지역일 경우와 사각형지역일 경우 모두에 적용가능한 지점)
 */
void Dot2Test_SetPacketParseData(struct V2XPacketParseData *parsed)
{
  parsed->spdu.signed_data.gen_time_present = true;
  parsed->spdu.signed_data.expiry_time_present = true;
  parsed->spdu.signed_data.gen_location_present = true;
  parsed->spdu.signed_data.gen_time = CERT_VALID_START + 1000ULL;
  parsed->spdu.signed_data.expiry_time = CERT_VALID_START + 2000ULL;
  parsed->spdu.signed_data.gen_location.lat = CERT_CIRCULAR_REGION_CENTER_LAT + CERT_RECTANGULAR_REGION_LAT_OFFSET_200M; // 1000m 반경 내
  parsed->spdu.signed_data.gen_location.lon = CERT_CIRCULAR_REGION_CENTER_LON + CERT_RECTANGULAR_REGION_LON_OFFSET_200M; // 1000m 반경 내
  parsed->spdu.signed_data.gen_location.elev = 0;
}


/**
 * @brief 기본 Security profile을 설정한다.
 * @param[out] sec_profile 설정할 security profile
 */
void Dot2Test_SetSecurityProfile(struct Dot2SecProfile *sec_profile)
{
  memset(sec_profile, 0, sizeof(struct Dot2SecProfile));
  sec_profile->rx.verify_data = true;
  sec_profile->rx.consistency_check.gen_location = true;
}


/**
 * @brief Circular 유형의 유효지역 정보를 갖는 인증서 정보 엔트리를 설정한다.
 * @param[out] entry 설정할 인증서 정보 엔트리
 */
void Dot2Test_SetSampleCircularSignerCertEntry(struct Dot2EECertCacheEntry *entry)
{
  entry->contents.common.valid_start = CERT_VALID_START;
  entry->contents.common.valid_end = CERT_VALID_END;;
  entry->contents.common.valid_region.type = kDot2CertValidRegionType_Circular;
  entry->contents.common.valid_region.u.circular.center.lat = CERT_CIRCULAR_REGION_CENTER_LAT;
  entry->contents.common.valid_region.u.circular.center.lon = CERT_CIRCULAR_REGION_CENTER_LON;
  entry->contents.common.valid_region.u.circular.radius = CERT_CIRCULAR_RADIUS;
}
