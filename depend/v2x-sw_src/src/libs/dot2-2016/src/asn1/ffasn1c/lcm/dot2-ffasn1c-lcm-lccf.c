/** 
  * @file 
  * @brief LCCF 관련 구현
  * @date 2022-07-09 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-ffasn1c.h"
#include "dot2-ffasn1c-inline.h"


/**
 * @brief LCCF를 파싱한다.
 * @param[in] lccf LCCF 바이트열
 * @param[in] lccf_size LCCF 바이트열의 길이
 * @param[out] ica_cert 생성된 RCA 인증서바이트열이 저장될 포인터 (사용 후 free()해 주어야 한다)
 * @param[out] ica_cert_size 생성된 RCA 인증서바이트열의 길이가 저장될 변수 포인터
 * @param[out] ica_cert 생성된 ICA 인증서바이트열이 저장될 포인터 (사용 후 free()해 주어야 한다)
 * @param[out] ica_cert_size 생성된 ICA 인증서바이트열의 길이가 저장될 변수 포인터
 * @param[out] pca_cert 생성된 ACA/PCA 인증서바이트열이 저장될 포인터 (사용 후 free()해 주어야 한다)
 * @param[out] pca_cert_size 생성된 ACA/PCA 인증서바이트열의 길이가 저장될 변수 포인터
 * @param[out] crlg_cert 생성된 CRLG 인증서바이트열이 저장될 포인터 (사용 후 free()해 주어야 한다)
 * @param[out] crlg_cert_size 생성된 CRLG 인증서바이트열의 길이가 저장될 변수 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 현재 RCA/ICA/ACA만 추출하고 있으나, 추후 필요에 따라 MA, CRLG 등의 추가가 가능.
 */
int INTERNAL dot2_ffasn1c_ParseLCCF(
  const uint8_t *lccf,
  Dot2LCCFSize lccf_size,
  uint8_t **rca_cert,
  Dot2CertSize *rca_cert_size,
  uint8_t **ica_cert,
  Dot2CertSize *ica_cert_size,
  uint8_t **pca_cert,
  Dot2CertSize *pca_cert_size,
  uint8_t **crlg_cert,
  Dot2CertSize *crlg_cert_size)
{
  Log(kDot2LogLevel_Event, "Parse %zu-bytes LCCF\n", lccf_size);

  dot2ScopedLocalCertificateChainFile *asn1_lccf = NULL;

  /*
   * LCCF를 디코딩한다.
   */
  ASN1Error asn1_err;
  asn1_ssize_t dec_size = asn1_oer_decode((void **)&asn1_lccf,
                                          asn1_type_dot2ScopedLocalCertificateChainFile,
                                          lccf,
                                          lccf_size,
                                          &asn1_err);
  if (dec_size < 0) {
    return -kDot2Result_ASN1_DecodeLCCF;
  }

  /*
   * LCCF에서 RCA, ICA, PCA, CRLG 인증서를 찾는다.
   */
  dot2Certificate *asn1_rca = NULL, *asn1_ica = NULL, *asn1_pca = NULL, *asn1_crlg = NULL;
  if ((asn1_lccf->content.choice == dot2ScmsFile_1_cert_chain) &&
      (asn1_lccf->content.u.cert_chain.choice == dot2CertificateChainFiles_localCertificateChainFile)) {
    dot2CertificateStore_3 *certs = &(asn1_lccf->content.u.cert_chain.u.localCertificateChainFile.requiredCertStore.certs);
    size_t certs_cnt = asn1_lccf->content.u.cert_chain.u.localCertificateChainFile.requiredCertStore.certs.count;
    for (size_t i = 0; i < certs_cnt; i++) {
      dot2Certificate *asn1_cert = (certs->tab + i);
      Dot2SCCCertType cert_type = dot2_ffasn1c_ParseSCCCertType(asn1_cert);
      if (cert_type == kDot2SCCCertType_RCA) {
        asn1_rca = asn1_cert;
      } else if (cert_type == kDot2SCCCertType_ICA) {
        asn1_ica = asn1_cert;
      } else if (cert_type == kDot2SCCCertType_PCA) {
        asn1_pca = asn1_cert;
      } else if (cert_type == kDot2SCCCertType_CRLG) {
        asn1_crlg = asn1_cert;
      }
    }
  }

  int ret = kDot2Result_Success;

  /*
   * 각 인증서를 인코딩하여 반환한다.
   */
  uint8_t *enc_rca_cert = NULL, *enc_ica_cert = NULL, *enc_pca_cert = NULL, *enc_crlg_cert = NULL;
  Dot2CertSize enc_rca_cert_size, enc_ica_cert_size, enc_pca_cert_size, enc_crlg_cert_size;
  if (asn1_rca) {
    enc_rca_cert = dot2_ffasn1c_EncodeCertificate((const dot2Certificate *)asn1_rca, &enc_rca_cert_size);
    if (enc_rca_cert == NULL) {
      ret = -kDot2Result_ASN1_EncodeLCCFRCACert;
      goto out;
    }
    *rca_cert = enc_rca_cert;
    *rca_cert_size = enc_rca_cert_size;
  }
  if (asn1_ica) {
    enc_ica_cert = dot2_ffasn1c_EncodeCertificate((const dot2Certificate *)asn1_ica, &enc_ica_cert_size);
    if (enc_ica_cert == NULL) {
      ret = -kDot2Result_ASN1_EncodeLCCFICACert;
      goto out;
    }
    *ica_cert = enc_ica_cert;
    *ica_cert_size = enc_ica_cert_size;
  }
  if (asn1_pca) {
    enc_pca_cert = dot2_ffasn1c_EncodeCertificate((const dot2Certificate *)asn1_pca, &enc_pca_cert_size);
    if (enc_pca_cert == NULL) {
      ret = -kDot2Result_ASN1_EncodeLCCFPCACert;
      goto out;
    }
    *pca_cert = enc_pca_cert;
    *pca_cert_size = enc_pca_cert_size;
  }
  if (asn1_crlg) {
    enc_crlg_cert = dot2_ffasn1c_EncodeCertificate((const dot2Certificate *)asn1_crlg, &enc_crlg_cert_size);
    if (enc_crlg_cert == NULL) {
      ret = -kDot2Result_ASN1_EncodeLCCFCRLGCert;
      goto out;
    }
    *crlg_cert = enc_crlg_cert;
    *crlg_cert_size = enc_crlg_cert_size;
  }

out:
  asn1_free_value(asn1_type_dot2ScopedLocalCertificateChainFile, asn1_lccf);
  return ret;
}
