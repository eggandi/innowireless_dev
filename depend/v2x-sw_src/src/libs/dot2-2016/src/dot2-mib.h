/**
 * @file
 * @brief libdot2 라이브러리 MIB 를 정의한 파일
 * @date 2020-02-18
 * @author gyun
 */


#ifndef V2X_SW_DOT2_MIB_H
#define V2X_SW_DOT2_MIB_H

// 시스템 헤더 파일
#include <pthread.h>

// 라이브러리 의존 헤더 파일
#include "openssl/ec.h"

// 라이브러리 내부 헤더 파일
#include "certificate/cert-info/dot2-cert-info.h"
#include "certificate/cert-info/dot2-ee-cert-cache.h"
#include "certificate/cert-info/dot2-scc-cert-info.h"
#include "certificate/cmh/dot2-cmh.h"
#include "sec-executer/dot2-sec-executer.h"
#include "sec-profile/dot2-sec-profile.h"
#include "spdu/dot2-spdu.h"


/**
 * @brief libdot2 라이브러리 MIB
 */
struct Dot2MIB
{
  pthread_mutex_t mtx; ///< MIB 정보 동시 접근을 제어하기 위한 뮤텍스

  struct Dot2SCCCertInfoTable scc_cert_info_table; ///< SCC인증서정보 저장소 테이블
  struct Dot2EECertCacheTable ee_cert_cache_table; ///< 타 장치(EE) 인증서캐시 저장소 테이블
  struct Dot2CMHTable cmh_table; ///< 내 CMH 저장소 테이블
  struct Dot2SecProfileTable sec_profile_table; ///< security profile 테이블
  struct Dot2SPDUProcess spdu_process; ///< SPDU 처리 기능
  struct Dot2SecExecuter sec_executer; ///< 보안연산 실행자
  Dot2LeapSeconds leap_secs; ///< 윤초

  struct {
    bool use; ///< 난수생성장치 사용 여부. false일 경우 난수생성을 위해 소프트웨어 random() 함수가 사용된다.
#define DOT2_RANDOM_DEV_MAX_LEN (50U)
    char name[DOT2_RANDOM_DEV_MAX_LEN+1]; ///< 난수생성장치 이름
  } rng_dev; ///< 라이브러리 내에서 사용되는 난수생성장치 정보

#ifdef _SUPPORT_SCMS_
  struct Dot2LCMInfo lcm; ///< LCM 관련정보
  struct Dot2CRLTable crl; ///< CRL 테이블
#endif

#if defined(_OBJASN1C_)
  OSCTXT ctxt_enc; ///< asn.1 인코더 컨텍스트
  OSCTXT ctxt_dec; ///< asn.1 디코더 컨텍스트
#endif
};

#endif //V2X_SW_DOT2_MIB_H
