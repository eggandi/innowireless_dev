/**
 * @file
 * @brief 등록인증서 발급응답문 관련 구현
 * @date 2022-05-03
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "certificate/cmhf/dot2-cmhf.h"
#if defined(_FFASN1C_)
#include "dot2-ffasn1c.h"
#elif defined(_OBJASN1C_)
#include "dot2-objasn1c.h"
#else
#error "3rd party asn.1 library is not defined"
#endif


/**
 * @brief 등록인증서 발급응답문을 처리한다.
 * @param[in] params 등록인증서 발급응답문의 처리를 위한 파라미터
 * @param[out] res 등록인증서 발급응답문 처리 결과가 저장될 구조체 포인터
 */
void INTERNAL
dot2_ProcessECResponse(struct Dot2ECResponseProcessParams *params, struct Dot2ECResponseProcessResult *res)
{
  Log(kDot2LogLevel_Event, "Process ECResponse\n");
  int ret;
  char *cmhf_name = NULL;
  uint8_t *cmhf = NULL;
  Dot2CMHFSize cmhf_size;

  /*
   * 등록인증서 발급응답문을 처리한다 -> requestHash(=H(ECRequest)) 값을 추출하여 파라미터로 전달된 값과 비교한다.
   * - 발급응답문 내에는 requestHash, ECA 인증서, 등록인증서, 개인키재구성값이 포함되어 있다.
   *   현재 이 중 ECA 인증서, 등록인증서, 개인키재구성값은 파라미터로도 제공(SCMS 서버가 파일로 제공)되므로 requestHash값만 추출한다.
   */
  bool req_h_matched = false;
  if (params->ec_resp) {
    uint8_t ec_req_h8[8];
#if defined(_FFASN1C_)
    ret = dot2_ffasn1c_ParseECResponse(params->ec_resp, params->ec_resp_size, ec_req_h8);
#elif defined(_OBJASN1C_)
    ret = dot2_objasn1c_ParseECResponse(params->ec_resp, params->ec_resp_size, ec_req_h8);
#else
#error "3rd party asn.1 library is not defined"
#endif
    if (ret < 0) {
      res->ret = ret;
      return;
    }
    if (memcmp(ec_req_h8, params->ec_req_h8, 8) == 0) {
      req_h_matched = true;
    }
  }

  /*
   * LCCF에서 RCA/ICA/PCA 인증서를 추출한다.
   */
  uint8_t *rca_cert = NULL, *ica_cert = NULL, *pca_cert = NULL, *crlg_cert = NULL;
  Dot2CertSize rca_cert_size, ica_cert_size, pca_cert_size, crlg_cert_size;
#if defined(_FFASN1C_)
  ret = dot2_ffasn1c_ParseLCCF(params->lccf,
                               params->lccf_size,
                               &rca_cert,
                               &rca_cert_size,
                               &ica_cert,
                               &ica_cert_size,
                               &pca_cert,
                               &pca_cert_size,
                               &crlg_cert,
                               &crlg_cert_size);
#elif defined(_OBJASN1C_)
  ret = dot2_objasn1c_ParseLCCF(params->lccf,
                                params->lccf_size,
                                &rca_cert,
                                &rca_cert_size,
                                &ica_cert,
                                &ica_cert_size,
                                &pca_cert,
                                &pca_cert_size,
                                &crlg_cert,
                                &crlg_cert_size);
#else
#error "3rd party asn.1 library is not defined"
#endif
  if (ret < 0) {
    goto err;
  }

  /*
   * LCCF 내 주요 인증서들을 SCC 정보리스트에 추가하여, 체인이 잘 구성되고 검증되는지 확인한다.
   * pca/ra/eca -> ica -> rca
   * - 기존에 저장된 인증서들과 동일한 경우 저장되지 않는다(성공이 반환된다)
   *
   * LCCF에 RCA인증서가 들어있지 않은 경우, 파라미터로 전달된 RCA인증서를 저장한다. (그래야 RCA의 하위인증서들의 저장이 가능하다)
   */
  if (rca_cert || ica_cert || pca_cert || crlg_cert) {
    if (!rca_cert) {
      rca_cert = params->rca_cert.octs;
      rca_cert_size = params->rca_cert.size;
    }
    pthread_mutex_lock(&(g_dot2_mib.mtx));
    ret = dot2_AddLCCFCertsToSCCList(rca_cert,
                                     rca_cert_size,
                                     ica_cert,
                                     ica_cert_size,
                                     pca_cert,
                                     pca_cert_size,
                                     crlg_cert,
                                     crlg_cert_size);
    pthread_mutex_unlock(&(g_dot2_mib.mtx));
    if (ret < 0) {
      Err("Fail to process ECResponse - cannot add LCCF cert to SCC list\n");
      goto err;
    }
  }

  /*
   * 등록인증서용 개인키/공개키를 재구성하고 CMHF를 생성한다.
   */
  struct Dot2ECPrivateKey priv_key;
  ret = dot2_MakeSequentialCMHFforImplicitCert_1(kDot2CMHType_Enrollment,
                                                 &(params->init_priv_key),
                                                 &(params->recon_priv),
                                                 &(params->ec),
                                                 &(params->eca_cert),
                                                 &cmhf_name,
                                                 &cmhf,
                                                 &cmhf_size,
                                                 &priv_key);
  if (ret < 0) {
    goto err;
  }

  /*
   * 결과를 반환변수에 저장한다. (아직 저장되지 않은 반환변수 대상)
   */
  res->ret = kDot2Result_Success;
  res->req_h_matched = req_h_matched;
  memcpy(&(res->enrollment_priv_key), &priv_key, sizeof(priv_key));
  res->enrollment_cmhf_name = cmhf_name;
  res->enrollment_cmhf = cmhf;
  res->enrollment_cmf_size = cmhf_size;
  if (rca_cert) {
    res->rca_cert = rca_cert;
    res->rca_cert_size = rca_cert_size;
  }
  if (ica_cert) {
    res->ica_cert = ica_cert;
    res->ica_cert_size = ica_cert_size;
  }
  if (pca_cert) {
    res->pca_cert = pca_cert;
    res->pca_cert_size = pca_cert_size;
  }
  if (crlg_cert) {
    res->crlg_cert = crlg_cert;
    res->crlg_cert_size = crlg_cert_size;
  }
  return;

err:
  res->ret = ret;
  if (rca_cert) { free(rca_cert); }
  if (ica_cert) { free(ica_cert); }
  if (pca_cert) { free(pca_cert); }
  if (crlg_cert) { free(crlg_cert); }
  if (cmhf_name) { free(cmhf_name); }
  if (cmhf) { free(cmhf); }
}
