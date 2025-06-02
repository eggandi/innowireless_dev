/** 
  * @file 
  * @brief ffasn1c 라이브러리를 이용한 EE 인증서 파싱 관련 구현
  * @date 2022-07-16 
  * @author gyun 
  */


// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "dot2-ffasn1c.h"
#include "dot2-ffasn1c-inline.h"


/**
 * @brief EE 인증서 바이트열로부터 인증서정보를 추출하여, 인증서컨테츠정보에 저장하여 반환한다.
 * @param[in] cert 인증서 바이트열
 * @param[in] cert_size 인증서 바이트열의 길이
 * @param[out] contents 추출된 인증서컨텐츠정보가 저장될 구조체 포인터
 * @param[out] err 실패 시 에러코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 인증서 디코딩정보 포인터
 * @retval NULL: 실패
 */
dot2Certificate INTERNAL * dot2_ffasn1c_ParseEECertContents_1(
  const uint8_t *cert,
  Dot2CertSize cert_size,
  struct Dot2EECertContents *contents,
  int *err)
{
  Log(kDot2LogLevel_Event, "Parse EE cert contents\n");

  /*
   * 인증서 바이트열을 asn.1 디코딩한다.
   */
  int ret;
  dot2Certificate *asn1_cert = dot2_ffasn1c_DecodeCertificate(cert, cert_size, &ret);
  if (asn1_cert == NULL) {
    *err = ret;
    return NULL;
  }

  /*
   * 인증서정보를 파싱한다.
   */
  ret = dot2_ffasn1c_ParseEECertContents_2(asn1_cert, contents);
  if (ret < 0) {
    goto err;
  }

  return asn1_cert;

err:
  asn1_free_value(asn1_type_dot2Certificate, asn1_cert);
  *err = ret;
  return NULL;
}


/**
 * @brief EE 인증서 바이트열로부터 인증서정보를 추출하여, 인증서컨테츠정보에 저장하여 반환한다.
 * @param[in] asn1_cert 인증서 asn1. 디코딩정보
 * @param[out] contents 추출된 인증서컨텐츠정보가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ParseEECertContents_2(const dot2Certificate *asn1_cert, struct Dot2EECertContents *contents)
{
  Log(kDot2LogLevel_Event, "Parse EE cert contents 2\n");

  /*
   * 인증서 공통컨텐츠정보를 파싱한다.
   */
  int ret = dot2_ffasn1c_ParseCertCommonContents(asn1_cert, &(contents->common));
  if (ret < 0) {
    return ret;
  }

  /*
   * 인증서 내 어플리케이션 권한을 파싱한다. (응용/식별/익명 인증서인 경우에 어플리케이션 권한, 등록인증서인 경우에 요청 권한)
   */
  if (asn1_cert->toBeSigned.appPermissions_option) {
    ret = dot2_ffasn1c_ParseCertAppPermissions(asn1_cert, &(contents->app_perms));
    if (ret < 0) {
      return ret;
    }
  } else if (asn1_cert->toBeSigned.certRequestPermissions_option) {
    ret = dot2_ffasn1c_ParseCertReqPermissions(asn1_cert, &(contents->app_perms));
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot2LogLevel_Event, "Success to parse EE cert contents 2\n");
  return kDot2Result_Success;
}


/**
 * @brief 인증서 디코딩정보를 파싱하여 어플리케이션권한정보에 저장한다.
 * @param[in] asn1_cert 인증서 디코딩정보
 * @param[out] to 파싱된 정보가 저장될 어플리케이션권한정보 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ParseCertAppPermissions(const dot2Certificate *asn1_cert, struct Dot2EECertPermissions *to)
{
  Log(kDot2LogLevel_Event, "Parse cert app perms\n");
  if (dot2_CheckCertPermssionsNum(asn1_cert->toBeSigned.appPermissions.count) == false) {
    return -kDot2Result_CERT_InvalidPermissionsCount;
  }
  to->psid_num = asn1_cert->toBeSigned.appPermissions.count;
  for (unsigned int i = 0; i < to->psid_num; i++) {
    dot2PsidSsp *perm = asn1_cert->toBeSigned.appPermissions.tab + i;
    int psid;
    if (asn1_integer_get_si_ov(&(perm->psid), &psid) == 0) {
      to->psid[i] = (Dot2PSID)psid;
    } else {
      return -kDot2Result_ASN1_ParseCertPermissions;
    }
  }
  return kDot2Result_Success;
}


/**
 * @brief 인증서 디코딩정보를 파싱하여 요청권한정보에 저장한다.
 * @param[in] asn1_cert 인증서 디코딩정보
 * @param[out] to 파싱된 정보가 저장될 요청권한정보 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * KISA v1.1 규격에 따라,
 * 등록인증서 내 certRequestPermssions는 1개 존재하며, 그 안에 다수의 subjectPermissions가 존재한다.
 *
 * 현재 dot2 라이브러리에서는 등록인증서 내 CertRequestPermissions만 처리한다.
 * (SCC 인증서들에 대해서는 권한저장을 하지 않는다)
 */
int INTERNAL dot2_ffasn1c_ParseCertReqPermissions(const dot2Certificate *asn1_cert, struct Dot2EECertPermissions *to)
{
  Log(kDot2LogLevel_Event, "Parse cert req perms\n");
  if (asn1_cert->toBeSigned.certRequestPermissions.count == 0) {
    Err("Fail to parse cert req perms - no req perms\n");
    return -kDot2Result_CERT_InvalidPermissionsCount;
  }
  dot2PsidGroupPermissions *perms = asn1_cert->toBeSigned.certRequestPermissions.tab;
  // Explicit 인 경우에만 저장한다.
  if (perms->subjectPermissions.choice == dot2SubjectPermissions_Explicit) {
    if (dot2_CheckCertPermssionsNum(perms->subjectPermissions.u.Explicit.count) == false) {
      Err("Fail to parse cert req perms - invalid subject perms num: %u\n", perms->subjectPermissions.u.Explicit.count);
      return -kDot2Result_CERT_InvalidPermissionsCount;
    }
    to->psid_num = perms->subjectPermissions.u.Explicit.count;
    for (unsigned int i = 0; i < to->psid_num; i++) {
      dot2PsidSspRange *perm = perms->subjectPermissions.u.Explicit.tab + i;
      int psid;
      if (asn1_integer_get_si_ov(&(perm->psid), &psid) == 0) {
        to->psid[i] = (Dot2PSID)psid;
      } else {
        return -kDot2Result_ASN1_ParseCertPermissions;
      }
    }
  }
  return kDot2Result_Success;
}
