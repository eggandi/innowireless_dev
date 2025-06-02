/** 
  * @file 
  * @brief SPDU consistency check 단위테스트에 사용되는 샘플 데이터를 정의한 파일
  * @date 2021-09-06 
  * @author gyun 
  */

#ifndef V2X_SW_TEST_CONSISTENCY_CHECK_SAMPLE_DATA_H
#define V2X_SW_TEST_CONSISTENCY_CHECK_SAMPLE_DATA_H


#define CERT_VALID_START (1000000000UL) // 인증서 유효기간 시작시점
#define CERT_VALID_END (2000000000UL) // 인증서 유효기간 종료시점
#define CERT_CIRCULAR_REGION_CENTER_LAT (374063230L) // 원형 유효지역을 갖는 인증서의 유효지역 중심점 위도
#define CERT_CIRCULAR_REGION_CENTER_LON (1271023340L) // 원형 유효지역을 갖는 인증서의 유효지역 중심점 경도
#define CERT_CIRCULAR_RADIUS (1000UL) // 원형 유효지역을 갖는 인증서의 유효지역 반지름

#define CERT_RECTANGULAR_REGION_LAT_OFFSET_200M (-25000L) // 사각형 유효지역을 갖는 인증서의 각 영역의 세로변 길이(대략적인 값)
#define CERT_RECTANGULAR_REGION_LON_OFFSET_200M (40000L) // 사각형 유효지역을 갖는 인증서의 각 영역의 세로변 길이(대략적인 값)
#define CERT_RECTANGULAR_REGION_0_NORTH_WEST_LAT (374087730L) // 사각형 유효지역을 갖는 인증서의 첫번째 영역의 북서지점 위도
#define CERT_RECTANGULAR_REGION_0_NORTH_WEST_LON (1270947620L) // 사각형 유효지역을 갖는 인증서의 첫번째 영역의 북서지점 위도
#define CERT_RECTANGULAR_REGION_0_SOUTH_EAST_LAT \
  (CERT_RECTANGULAR_REGION_0_NORTH_WEST_LAT + CERT_RECTANGULAR_REGION_LAT_OFFSET_200M) \
  // 사각형 유효지역을 갖는 인증서의 첫번째 영역의 남동지점 위도
#define CERT_RECTANGULAR_REGION_0_SOUTH_EAST_LON \
  (CERT_RECTANGULAR_REGION_0_NORTH_WEST_LON + CERT_RECTANGULAR_REGION_LON_OFFSET_200M) \
  // 사각형 유효지역을 갖는 인증서의 첫번째 영역의 남동지점 경도

#define SPDU_LAT_TOO_FAR_FROM_CERT_VALID_REGION (373794460L) // 인증서 유효지역으로부터 너무 먼 지점의 위도
#define SPDU_LON_TOO_FAR_FROM_CERT_VALID_REGION (1270997130L) // 인증서 유효지역으로부터 너무 먼 지점의 경도

void Dot2Test_SetPacketParseData(struct V2XPacketParseData *parsed);
void Dot2Test_SetSecurityProfile(struct Dot2SecProfile *sec_profile);
void Dot2Test_SetSampleCircularSignerCertEntry(struct Dot2EECertCacheEntry *entry);


#endif //V2X_SW_TEST_CONSISTENCY_CHECK_SAMPLE_DATA_H
