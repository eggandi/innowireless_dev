/** 
  * @file 
  * @brief 보안연산실행자 관련 정의
  * @date 2022-07-02 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_SEC_EXECUTER_H
#define V2X_SW_DOT2_SEC_EXECUTER_H


// 라이브러리 내부 헤더 파일
#include "sec-executer/openssl/dot2-openssl.h"
#if defined(_SIGN_VERIFY_SAF5400_)
#include "sec-executer/saf5400/dot2-saf5400.h"
#endif


/**
 * @brief 보안연산실행자 정보
 */
struct Dot2SecExecuter
{
  struct Dot2OsslSecExecuter ossl; ///< openssl 보안연산실행자 정보
#if defined(_SIGN_VERIFY_SAF5400_)
  struct Dot2SAF5400Executer saf5400; ///< saf54000 보안 연산 실행자 정보 (서명검증에만 사용된다)
#elif defined(_SIGN_VERIFY_CRATON2_)
  struct Dot2Craton2Executer craton2; ///< craton2 보안 연산 실행자 정보 (현재 서명검증에만 사용된다)
#endif
};


#endif //V2X_SW_DOT2_SEC_EXECUTER_H
