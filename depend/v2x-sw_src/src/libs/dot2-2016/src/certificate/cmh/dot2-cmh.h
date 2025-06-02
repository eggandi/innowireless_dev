/** 
 * @file
 * @brief End-Entity CMH(Crypto Material Handle - 개인키+인증서정보 묶음) 관련 정의
 * @date 2020-03-20
 * @author gyun
 */

#ifndef V2X_SW_DOT2_CMH_H
#define V2X_SW_DOT2_CMH_H


// 시스템 헤더 파일
#include <stdint.h>

// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-types.h"
#include "certificate/cmh/dot2-cmh-rotate.h"
#include "certificate/cmh/dot2-cmh-sequential.h"


/**
 * @brief CMH 유형
 */
enum eDot2CMHType
{
  kDot2CMHType_Undefined, ///< CMH 유형이 아직 결정되지 않음
  kDot2CMHType_Application, ///< Application 인증서 CMH
  kDot2CMHType_Identification, ///< Identificatioin 인증서 CMH
  kDot2CMHType_Pseudonym, ///< Pseudonym 인증서 CMH
  kDot2CMHType_Enrollment, ///< Enrollment 인증서 CMH
  kDot2CMHType_Max = kDot2CMHType_Enrollment,
};
typedef unsigned int Dot2CMHType; ///< @ref eDot2CMHType


/**
 * @brief 개인키 정보 유형
 */
enum eDot2PrivKeyType
{
  kDot2PrivKeyType_Key, ///< 개인키
  kDot2PrivKeyType_Idx, ///< 개인키 인덱스(개인키 대신 개인키 인덱스 사용)
  kDot2PrivKeyType_Max = kDot2PrivKeyType_Idx ///< 최대값
};
typedef unsigned int Dot2PrivKeyType; ///< @ref eDot2PrivKeyType


/**
 * @brief CMH(Crypto Material Handle) 테이블 형식
 *
 * 나의 CMH 정보들이 저장된다.
 */
struct Dot2CMHTable
{
  Dot2CMHType cmh_type; ///< CMH 유형 (각 EE는 응용/식별/익명 인증서 중 한 종류의 인증서만을 사용한다)
  struct Dot2SequentialCMHList app; ///< 응용인증서 관련 CMH 리스트
  struct Dot2RotateCMHSetList pseudonym_id; ///< 익명/식별인증서 관련 CMH 세트 리스트
  struct Dot2SequentialCMHList enrol; ///< 등록인증서 관련 CMH 리스트
};


#endif //V2X_SW_DOT2_CMH_H
