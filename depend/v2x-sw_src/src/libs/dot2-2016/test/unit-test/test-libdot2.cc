/** 
 * @file
 * @brief 단위테스트 메인 파일 - main() 함수 정의
 * @date 2020-02-18
 * @author gyun
 */


// google test 헤더 파일
#include "gtest/gtest.h"


/**
 * @brief 정의된 모든 단위테스트를 수행한다.
 */
int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
