/** 
  * @file 
  * @brief CMHF 관련 API 구현
  * @date 2022-07-16 
  * @author gyun 
  */



// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "certificate/cmhf/dot2-cmhf.h"
#if defined(_FFASN1C_)
#include "asn1/ffasn1c/dot2-ffasn1c.h"
#elif defined(_OBJASN1C_)
#include "asn1/objasn1c/dot2-objasn1c.h"
#else
#error "3rd party asn.1 library is not defined"
#endif


/**
 * @brief 웅용인증서 CMHF 생성 요청 파라미터의 유효성을 체크한다.
 * @param[in] params 웅용인증서 CMHF 생성 요청 파라미터
 * @retval 0: 유효함
 * @retval 음수(-Dot2Result_Code): 유효하지 않음
 */
static int dot2_CheckAppCMHFMakeParams(struct Dot2AppCMHFMakeParams *params)
{
  if ((dot2_CheckCertSize(params->cert.size) == false) ||
      (dot2_CheckCertSize(params->issuer.size) == false)) {
    return -kDot2Result_CERT_InvalidCertSize;
  }
  return kDot2Result_Success;
}


/**
 * @brief Application 인증서와 개인키재구성정보를 이용하여 CMHF를 생성한다(상세 내용 API 매뉴얼 참조)
 * @param[in] params 생성요청 파라미터
 * @return CMHF 생성 결과
 *
 * LCM을 사용하지 않고, 수동으로 발급받은 인증서번들을 이용하여 CMHF를 생성할 때 사용된다.
 * 반환되는 개인키는 실제로는 사용되지 않고 참고용이다 (실제 서명생성 시에는 CMHF에 포함된 포함된 개인키정보가 사용된다)
 */
struct Dot2CMHFMakeResult OPEN_API Dot2_MakeApplicationCertCMHF(struct Dot2AppCMHFMakeParams *params)
{
  Log(kDot2LogLevel_Event, "Make application cert CMHF\n");
  struct Dot2CMHFMakeResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    res.ret = -kDot2Result_NullParameters;
    return res;
  }
  int ret = dot2_CheckAppCMHFMakeParams(params);
  if (ret < 0) {
    Err("Fail to make application cert CMHF - dot2_CheckAppCMHFMakeParams() failed\n");
    res.ret = ret;
    return res;
  }

  /*
   * 상위인증서에 대한 해시를 계산한다.
   */
  struct Dot2SHA256 issuer_h;
  SHA256(params->issuer.octs, params->issuer.size, issuer_h.octs);

  /*
   * CMHF를 생성한다.
   */
  char *cmhf_name = NULL;
  uint8_t *cmhf = NULL;
  Dot2CMHFSize cmhf_size;
  ret = dot2_MakeSequentialCMHFforImplicitCert_1(kDot2CMHType_Application,
                                                 &(params->init_priv_key),
                                                 &(params->recon_priv),
                                                 &(params->cert),
                                                 &(params->issuer),
                                                 &cmhf_name,
                                                 &cmhf,
                                                 &cmhf_size,
                                                 &(res.priv_key));
  if (ret < 0) {
    res.ret = ret;
    return res;
  }

  /*
   * 결과를 반환한다.
   */
  res.cmhf_name = cmhf_name;
  res.cmhf = cmhf;
  res.cmhf_size = cmhf_size;
  Log(kDot2LogLevel_Event, "Success to make application cert CMHF\n");
  return res;
}


/**
 * @brief 익명인증서 CMHF 생성 요청 파라미터의 유효성을 체크한다.
 * @param[in] params 익명인증서 CMHF 생성 요청 파라미터
 * @retval 0: 유효함
 * @retval 음수(-Dot2Result_Code): 유효하지 않음
 */
static int dot2_CheckPseudonymCMHFMakeParams(struct Dot2PseudonymCMHFMakeParams *params)
{
  if (params->j_max != kDot2CertJvalue_PseudonymMax) {
    return -kDot2Result_CMHF_InvalidJMax;
  }
  for (unsigned int j = 0; j <= params->j_max; j++) {
    if(dot2_CheckCertSize(params->certs[j].size) == false) {
      return -kDot2Result_CERT_InvalidCertSize;
    }
  }
  if (dot2_CheckCertSize(params->issuer.size) == false) {
    return -kDot2Result_CERT_InvalidCertSize;
  }
  return kDot2Result_Success;
}


/**
 * @brief Pseudonym 인증서와 개인키재구성정보를 이용하여 CMHF를 생성한다(상세 내용 API 매뉴얼 참조)
 * @param[in] params 생성요청 파라미터
 * @return CMHF 생성 결과
 *
 * LCM을 사용하지 않고, 수동으로 발급받은 인증서번들을 이용하여 CMHF를 생성할 때 사용된다.
 * 반환되는 개인키는 실제로는 사용되지 않고 참고용이다 (실제 서명생성 시에는 CMHF에 포함된 포함된 개인키정보가 사용된다)
 */
struct Dot2PseudonymCMHFMakeResult OPEN_API Dot2_MakePseudonymCertCMHF(struct Dot2PseudonymCMHFMakeParams *params)
{
  Log(kDot2LogLevel_Event, "Make pseudonym cert CMHF\n");
  struct Dot2PseudonymCMHFMakeResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    res.ret = -kDot2Result_NullParameters;
    return res;
  }
  int ret = dot2_CheckPseudonymCMHFMakeParams(params);
  if (ret < 0) {
    Err("Fail to make pseudonym cert CMHF - dot2_CheckPseudonymCMHFMakeParams() failed\n");
    res.ret = ret;
    return res;
  }

  char *cmhf_name = NULL;
  uint8_t *cmhf = NULL;
  Dot2CMHFSize cmhf_size;
  ret = dot2_MakeRotateCMHFforImplicitCert_1(kDot2CMHType_Pseudonym,
                                             params->i,
                                             params->j_max,
                                             &(params->exp_key),
                                             &(params->seed_priv),
                                             params->certs,
                                             params->recon_privs,
                                             &(params->issuer),
                                             &cmhf_name,
                                             &cmhf,
                                             &cmhf_size,
                                             res.priv_keys);
  if (ret < 0) {
    res.ret = ret;
    return res;
  }

  /*
   * 결과를 반환한다.
   */
  res.cmhf_name = cmhf_name;
  res.cmhf = cmhf;
  res.cmhf_size = cmhf_size;
  Log(kDot2LogLevel_Event, "Success to make pseudonym cert CMHF\n");
  return res;
}


/**
 * @brief 식별인증서 CMHF 생성 요청 파라미터의 유효성을 체크한다.
 * @param[in] params 식별인증서 CMHF 생성 요청 파라미터
 * @retval 0: 유효함
 * @retval 음수(-Dot2Result_Code): 유효하지 않음
 */
static int dot2_CheckIdCMHFMakeParams(struct Dot2IdCMHFMakeParams *params)
{
  if (dot2_CheckCertSize(params->cert.size) == false) {
    return -kDot2Result_CERT_InvalidCertSize;
  }
  if (dot2_CheckCertSize(params->issuer.size) == false) {
    return -kDot2Result_CERT_InvalidCertSize;
  }
  return kDot2Result_Success;
}


/**
 * @brief Identification 인증서와 개인키재구성정보를 이용하여 CMHF를 생성한다(상세 내용 API 매뉴얼 참조).
 * @param[in] params 생성요청 파라미터
 * @return CMHF 생성 결과
 *
 * LCM을 사용하지 않고, 수동으로 발급받은 인증서번들을 이용하여 CMHF를 생성할 때 사용된다.
 * 반환되는 개인키는 실제로는 사용되지 않고 참고용이다 (실제 서명생성 시에는 CMHF에 포함된 포함된 개인키정보가 사용된다)
 */
struct Dot2IdCMHFMakeResult OPEN_API Dot2_MakeIdentificationCertCMHF(struct Dot2IdCMHFMakeParams *params)
{
  Log(kDot2LogLevel_Event, "Make identification cert CMHF\n");
  struct Dot2IdCMHFMakeResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    res.ret = -kDot2Result_NullParameters;
    return res;
  }
  int ret = dot2_CheckIdCMHFMakeParams(params);
  if (ret < 0) {
    Err("Fail to make identification cert CMHF - dot2_CheckIdCMHFMakeParams() failed\n");
    res.ret = ret;
    return res;
  }

  /*
   * 상위인증서 해시를 계산한다.
   */
  struct Dot2SHA256 issuer_h;
  SHA256(params->issuer.octs, params->issuer.size, issuer_h.octs);

  char *cmhf_name = NULL;
  uint8_t *cmhf = NULL;
  Dot2CMHFSize cmhf_size;
  ret = dot2_MakeRotateCMHFforImplicitCert_1(kDot2CMHType_Identification,
                                             params->i,
                                             kDot2CertJvalue_IdMax,
                                             &(params->exp_key),
                                             &(params->seed_priv),
                                             &(params->cert),
                                             &(params->recon_priv),
                                             &(params->issuer),
                                             &cmhf_name,
                                             &cmhf,
                                             &cmhf_size,
                                             &(res.priv_key));
  if (ret < 0) {
    res.ret = ret;
    return res;
  }

  /*
   * 결과를 반환한다.
   */
  res.cmhf_name = cmhf_name;
  res.cmhf = cmhf;
  res.cmhf_size = cmhf_size;
  Log(kDot2LogLevel_Event, "Success to make identification cert CMHF\n");
  return res;
}


/**
 * @brief CMHF 바이트열로부터 정보를 추출하여 CMH 저장소에 추가한다(상세 내용 API 매뉴얼 참조).
 * @param[in] cmhf CMHF 바이트열
 * @param[in] cmhf_size CMHF 바이트열의 길이
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int OPEN_API Dot2_LoadCMHF(const uint8_t *cmhf, Dot2CMHFSize cmhf_size)
{
  Log(kDot2LogLevel_Event, "Load %zu-bytes CMHF\n", cmhf_size);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (!cmhf) {
    return -kDot2Result_NullParameters;
  }
  if (dot2_CheckCMHFSize(cmhf_size) == false) {
    return -kDot2Result_CMHF_InvalidSize;
  }

  return dot2_LoadCMHF(cmhf, cmhf_size);
}


/**
 * @brief CMHF 파일로부터 정보를 추출하여 CMH 저장소에 추가한다(상세 내용 API 매뉴얼 참조).
 * @param[in] file_path CMHF 파일 경로(상대경로 및 절대경로 모두 가능)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int OPEN_API Dot2_LoadCMHFFile(const char *file_path)
{
  Log(kDot2LogLevel_Event, "Load CMHF file\n");

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (file_path == NULL) {
    return -kDot2Result_NullParameters;
  }

  return dot2_LoadCMHFFile(file_path);
}


#if 0 // TODO::
/**
 * @brief 현재 가용한 CMH들의 전체 유효기간을 확인한다.
 */
int OPEN_API Dot2_GetCMHFValidPeriod()
{

}
#endif
