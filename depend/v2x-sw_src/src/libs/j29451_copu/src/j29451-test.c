/** 
  * @file 
  * @brief 단위테스트 관련 기능 (단위테스트 수행시에만 사용된다)
  * @date 2022-09-16 
  * @author gyun 
  */


#ifdef _UNIT_TEST_

// 라이브러리 내부 헤더 파일
#include "j29451-test.h"

struct J29451TestGPSData g_test_gps_data[TEST_GNSS_DATA_NUM];
int g_test_gps_data_idx = -1;

#endif
