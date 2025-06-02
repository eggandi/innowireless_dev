/** 
  * @file 
  * @brief EE 인증서 관련 정의
  * @date 2022-07-15 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_EE_CERT_INFO_H
#define V2X_SW_DOT2_EE_CERT_INFO_H


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief EE 인증서컨텐츠 정보 형식
 *
 * EE 인증서 내에 포함된 정보들이 저장된다.
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라;
 *  - EE 인증서는 Implicit 인증서이다 -> 서명검증용공개키 재구성값이 포함된다.
 */
struct Dot2EECertContents
{
  struct Dot2CertCommonContents common; ///< 인증서 공통 컨텐츠 정보
  struct Dot2EECertPermissions app_perms; ///< 어플리케이션 권한(응용/식별/익명인증서인 경우) 또는 요청 권한(등록인증서인 경우)
  struct Dot2ECPublicKey verify_pub_key; ///< 재구성된 서명검증용공개키 바이트열
#ifdef _SIGN_VERIFY_OPENSSL_
  EC_KEY *eck_verify_pub_key; ///< 재구성된 EC_KEY 형식 서명검증용공개키 (동적 할당됨 -> EC_KEY_free()로 해제되어야 함)
#endif
};


#endif //V2X_SW_DOT2_EE_CERT_INFO_H
