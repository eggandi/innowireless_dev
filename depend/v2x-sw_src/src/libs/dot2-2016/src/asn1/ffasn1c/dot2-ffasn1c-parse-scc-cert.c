/** 
  * @file 
  * @brief ffasn1c 라이브러리를 이용한 SCC 인증서 파싱 관련 구현
  * @date 2022-07-16 
  * @author gyun 
  */


// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-ffasn1c.h"
#include "dot2-ffasn1c-inline.h"


/**
 * @brief SCC인증서 바이트열로부터 인증서정보를 추출하여, 인증서컨텐츠정보와 서명정보에 저장하여 반환한다.
 * @param[in] cert 인증서 바이트열
 * @param[in] cert_size 인증서 바이트열의 길이
 * @param[out] contents 추출된 인증서정보가 저장될 인증서컨텐츠정보 구조체 포인터
 * @param[out] sign 추출된 서명정보가 저장될 서명정보 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ParseSCCCertContents(
  const uint8_t *cert,
  Dot2CertSize cert_size,
  struct Dot2SCCCertContents *contents,
  struct Dot2Signature *sign)
{
  Log(kDot2LogLevel_Event, "Parse SCC cert contents\n");

  /*
   * 인증서 바이트열을 asn.1 디코딩한다.
   */
  int ret;
  dot2Certificate *asn1_cert = dot2_ffasn1c_DecodeCertificate(cert, cert_size, &ret);
  if (asn1_cert == NULL) {
    Err("Fail to parse SCC cerrt contents - dot2_ffasn1c_DecodeCertificate() failed\n");
    return ret;
  }

  /*
   * 인증서 공통정보를 파싱한다.
   */
  ret = dot2_ffasn1c_ParseCertCommonContents(asn1_cert, &(contents->common));
  if (ret < 0) {
    goto out;
  }

  /*
   * 권한정보를 파싱하여 인증서의 유형을 파악한다.
   */
  contents->type = dot2_ffasn1c_ParseSCCCertType(asn1_cert);
  if (contents->type == kDot2SCCCertType_Unknown) {
    Err("Fail to parse SCC ert contents - invalid cert type: %u\n", contents->type);
    ret = -kDot2Result_CERT_InvalidSCCCertType;
    goto out;
  }

  /*
   * 서명(signature) 정보를 파싱하여 저장한다.
   */
  if (asn1_cert->signature_option == true) {
    ret = dot2_ffasn1c_ParseSignature(&(asn1_cert->signature), sign);
  } else {
    Err("Fail to parse SCC cert contents - no signature in cert\n");
    ret = -kDot2Result_NoSignatureInCACert;
  }

  if (ret == kDot2Result_Success) {
    Log(kDot2LogLevel_Event, "Success to parse SCC cert contents\n");
  }

out:
  asn1_free_value(asn1_type_dot2Certificate, asn1_cert);
  return ret;
}
