/**
  * @file
  * @brief CRL 관련 구현
  * @date 2022-12-10
  * @author gyun
  */


// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "asn1/ffasn1c/dot2-ffasn1c.h"
#include "asn1/ffasn1c/dot2-ffasn1c-inline.h"
#include "lcm/dot2-lcm-inline.h"


/**
 * @brief CRL contents의 유효성을 검증한다.
 * @param[in] current 현재시각
 * @param[in] asn_contents CRL contents 디코딩 정보
 * @return 유효한지 여부
 *
 * KISA 규격에 따르면, CRL 정보를 사용하고자 하는 시점은 CRL의 게시 일자(issueDate)와 다음 갱신일자(nextCrl) 사이여야 한다.
 */
static inline bool dot2_ffasn1c_CheckCRLContentsValid(Dot2Time32 current, dot2CrlContents *asn_contents)
{
  int ret = ((current >= asn_contents->issueDate) && (current <= asn_contents->nextCrl)) ? true : false;
#ifdef _UNIT_TEST_
  if (g_dot2_mib.lcm.test.crl.ignore_valid_period) {
    ret = true;
  }
#endif
  return ret;
}


/**
 * @brief Hash 기반 CRL을 이용하여 EE 인증서들을 폐기한다.
 * @param[in] current 현재시각
 * @param[in] asn_crl CRL 디코딩 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_RevokeEECertsUsingHashBasedCRL(Dot2Time32 current, dot2ToBeSignedHashIdCrl *asn_crl)
{
  Log(kDot2LogLevel_Event, "Revoke EE certs using hash-based CRL\n");

  /*
   * CRL contents에 들어 있는 HashedId10에 대한 인증서폐기정보들을 CRL 테이블에 저장한다.
   */
  dot2HashBasedRevocationInfo *revok_info;
  for (size_t i = 0; i < asn_crl->entries.count; i++) {
    revok_info = asn_crl->entries.tab + i;
    if ((revok_info) &&
        (revok_info->expiry >= current) && // 폐기정보가 만기되지 않고
        (revok_info->id.buf) && // HashedId10 정보 존재
        (revok_info->id.len == 10)) { // HashedId10 길이 유효
      dot2_AddHashBasedCertRevocationEntry(revok_info->id.buf);
    }
  }
  return kDot2Result_Success;
}


/**
 * @brief Linkage value 값을 이용하여 EE 인증서정보를 폐기시킨다. (CRL 테이블에 저장한다)
 * @param[in] i_rev CRL 내 iRev 값 (폐기정보 유효기간 시작시점)
 * @param[in] i_max CRL 내 iMax 값 (폐기정보 유효기간 종료시점)
 * @param[in] j_max CRL 내 jMax 값 (유효한 인증서 개수)
 * @param[in] la1_id CRL 내 LA1 ID (Linkage seed 1 값을 생성한 LA 식별자)
 * @param[in] la2_id CRL 내 LA2 ID (Linkage seed 2 값을 생성한 LA 식별자)
 * @param[in] ls1 CRL 내 Linkage seed 1 값
 * @param[in] ls2 CRL 내 Linkage seed 2 값
 *
 * "KISA V2X 인증서 폐지 목록 검증 규격 v1.1"의 8.2.1 절의 메커니즘에 따라 처리한다.
 * 현 시점의 i-period에 해당되는 폐기정보만을 테이블에 저장한다.
 */
void INTERNAL dot2_ffasn1c_RevokeEECertUsingLinkageValue(
  uint16_t i_rev,
  uint16_t i_max,
  uint8_t j_max,
  const uint8_t *la1_id,
  const uint8_t *la2_id,
  const uint8_t *ls1,
  const uint8_t *ls2)
{
  Log(kDot2LogLevel_Event, "Revoke EE cert using linkage value\n");
  Log(kDot2LogLevel_Event, " iRev: %u, iMax: %u, jMax: %u, LA1ID: 0x%02X%02X, LA2ID: 0x%02X%02X\n",
      i_rev, i_max, j_max, *la1_id, *(la1_id + DOT2_LA_ID_LEN - 1), *la2_id, *(la2_id + DOT2_LA_ID_LEN - 1));
  Log(kDot2LogLevel_Event, " LS1: 0x%02X..%02X, LS2: 0x%02X..%02X\n",
      *ls1, *(ls1 + DOT2_LINKAGE_SEED_LEN - 1), *ls2, *(ls2 + DOT2_LINKAGE_SEED_LEN - 1));

  /*
   * 현 시점의 iCert(=i-period) 값을 구한다.
   */
  uint16_t i_cert = (uint16_t)dot2_GetCurrentIPeriod();

  /*
   * iCert > iMax이면, 폐기정보가 더 이상 의미없는 과거 정보이므로 본 폐기정보를 무시한다.
   *  - "KISA V2X 인증서 폐지 목록 검증 규격 v1.1" 8.2.1 절의 "가)" 절차
   */
  if (i_cert > i_max) {
    Log(kDot2LogLevel_Event, "Not revoke EE cert using linkage value - iCert(%u) > iMax(%u)\n", i_cert, i_max);
    return;
  }

  /*
   * Linkage seed 1/2 값을 구한다.
   *  - "KISA V2X 인증서 폐지 목록 검증 규격 v1.1" 8.2.1 절의 "나)" 절차
   */
  uint8_t ls1_final[DOT2_LINKAGE_SEED_LEN], ls2_final[DOT2_LINKAGE_SEED_LEN];
  dot2_CalculateLinkageSeed(i_rev, i_cert, la1_id, la2_id, ls1, ls2, ls1_final, ls2_final);

  /*
   * j 값을 0부터 jMax-1까지 반복하면서 lv(j)값을 계산하여 CRL 테이블에 저장한다.
   *  - "KISA V2X 인증서 폐지 목록 검증 규격 v1.1" 8.2.1 절의 "다)" 절차
   */
  uint8_t lv_j[DOT2_LINKAGE_VALUE_LEN];
  for (uint8_t j = 0; j < j_max; j++) {
    int ret = dot2_ossl_DeriveLinkageValue_j(j, la1_id, la2_id, ls1_final, ls2_final, lv_j);
    if (ret == kDot2Result_Success) {
      dot2_AddLVBasedCertRevocationEntry(i_cert, lv_j);
    }
  }
}


/**
 * @brief Linkage 기반 CRL을 이용하여 EE 인증서들을 폐기한다.
 * @param[in] asn_crl CRL 디코딩 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_RevokeEECertsUsingLinkageBasedCRL(dot2ToBeSignedLinkageValueCrl *asn_crl)
{
  Log(kDot2LogLevel_Event, "Revoke EE certs using linkage-based CRL\n");

  uint16_t irev = asn_crl->iRev;
  if (asn_crl->individual_option == false) {
    Err("Fail to revoke EE certs using linkage-based CRL - no individual info\n");
    return -kDot2Result_CRL_InvalidContents;
  }

  struct dot2JMaxGroup *jmax_grp;
  for (size_t i = 0; i < asn_crl->individual.count; i++) {
    jmax_grp = asn_crl->individual.tab + i;
    if (jmax_grp) {
      uint8_t jmax = jmax_grp->jmax;
      dot2LAGroup *la_grp;
      for (size_t j = 0; j < jmax_grp->contents.count; j++) {
        la_grp = jmax_grp->contents.tab + j;
        if ((la_grp) &&
            (la_grp->la1Id.buf) &&
            (la_grp->la1Id.len == DOT2_LA_ID_LEN) &&
            (la_grp->la2Id.buf) &&
            (la_grp->la2Id.len == DOT2_LA_ID_LEN)) {
          uint8_t *la1_id = la_grp->la1Id.buf;
          uint8_t *la2_id = la_grp->la2Id.buf;
          dot2IMaxGroup *imax_grp;
          for (size_t k = 0; k < la_grp->contents.count; k++) {
            imax_grp = la_grp->contents.tab + k;
            if (imax_grp) {
              uint16_t imax = imax_grp->iMax;
              dot2IndividualRevocation *revok;
              for (size_t l = 0; l < imax_grp->contents.count; l++) {
                revok = imax_grp->contents.tab + l;
                if ((revok) &&
                    (revok->linkage_seed1.buf) &&
                    (revok->linkage_seed1.len == DOT2_LINKAGE_SEED_LEN) &&
                    (revok->linkage_seed2.buf) &&
                    (revok->linkage_seed2.len == DOT2_LINKAGE_SEED_LEN)) {
                  uint8_t *ls1 = revok->linkage_seed1.buf;
                  uint8_t *ls2 = revok->linkage_seed2.buf;
                  dot2_ffasn1c_RevokeEECertUsingLinkageValue(irev, imax, jmax, la1_id, la2_id, ls1, ls2);
                }
              }
            }
          }
        }
      }
    }
  }
  return kDot2Result_Success;
}


/**
 * @brief CRL을 이용하여 EE 인증서들을 폐기한다.
 * @param[in] current 현재시각
 * @param[in] asn_contents CRL contents 디코딩 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_RevokeEECerts(Dot2Time32 current, dot2CrlContents *asn_contents)
{
  Log(kDot2LogLevel_Event, "Revoke EE certs\n");

  /*
   * CRL 유형별로 처리한다.
   */
  int ret;
  switch (asn_contents->typeSpecific.choice) {
    case dot2CrlContents_1_fullHashCrl:
      ret = dot2_ffasn1c_RevokeEECertsUsingHashBasedCRL(current, &(asn_contents->typeSpecific.u.fullHashCrl));
      break;
    case dot2CrlContents_1_deltaHashCrl:
      ret = dot2_ffasn1c_RevokeEECertsUsingHashBasedCRL(current, &(asn_contents->typeSpecific.u.deltaHashCrl));
      break;
    case dot2CrlContents_1_fullLinkedCrl:
      ret = dot2_ffasn1c_RevokeEECertsUsingLinkageBasedCRL(&(asn_contents->typeSpecific.u.fullLinkedCrl));
      break;
    case dot2CrlContents_1_deltaLinkedCrl:
      ret = dot2_ffasn1c_RevokeEECertsUsingLinkageBasedCRL(&(asn_contents->typeSpecific.u.deltaLinkedCrl));
      break;
    default:
      Err("Fail to revoke SCC certs - invalid type specific %d\n", asn_contents->typeSpecific.choice);
      ret = -kDot2Result_CRL_InvalidContents;
  }
  return ret;
}


/**
 * @brief Hash 기반 CRL을 이용하여 SCC 인증서들을 폐기한다.
 * @param[in] current 현재시각
 * @param[in] asn_contents CRL contents 디코딩 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_RevokeSCCCertsUsingHashBasedCRL(Dot2Time32 current, dot2CrlContents *asn_contents)
{
  Log(kDot2LogLevel_Event, "Revoke SCC certs\n");

  /*
   * CRL contents 내 CRL 유형을 확인한다.
   */
  dot2ToBeSignedHashIdCrl *asn_crl;
  switch (asn_contents->typeSpecific.choice) {
    case dot2CrlContents_1_fullHashCrl:
      asn_crl = &(asn_contents->typeSpecific.u.fullHashCrl);
      break;
    case dot2CrlContents_1_deltaHashCrl:
      asn_crl = &(asn_contents->typeSpecific.u.deltaHashCrl);
      break;
    default:
      Err("Fail to revoke SCC certs - invalid type specific %d\n", asn_contents->typeSpecific.choice);
      return -kDot2Result_CRL_InvalidContents;
  }

  /*
   * CRL contents에 들어 있는 HashedId10에 대한 인증서폐기정보들을 CRL 테이블에 저장한다.
   */
  dot2HashBasedRevocationInfo *revok_info;
  for (size_t i = 0; i < asn_crl->entries.count; i++) {
    revok_info = asn_crl->entries.tab + i;
    if ((revok_info) &&
        (revok_info->expiry >= current) && // 폐기정보가 만기되지 않고
        (revok_info->id.buf) && // HashedId10 정보 존재
        (revok_info->id.len == 10)) { // HashedId10 길이 유효
      dot2_AddHashBasedCertRevocationEntry(revok_info->id.buf);
    }
  }

  return kDot2Result_Success;
}


/**
 * @brief CRL contents를 이용하여 인증서들을 폐지한다.
 * @param[in] current 현재시각
 * @param[in] asn_contents CRL contents 디코딩 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_RevokeCertsUsingCRLContents(Dot2Time32 current, dot2CrlContents *asn_contents)
{
  Log(kDot2LogLevel_Event, "Revoke certs using CRL contents\n");

  int ret = kDot2Result_Success;
  Dot2CertCRLSeries crl_series = (Dot2CertCRLSeries)(asn_contents->crlSeries);
  switch (crl_series) {
    case kDot2CertCRLSeries_ObuPseudonym:
    case kDot2CertCRLSeries_EeNonPseudonym:
      ret = dot2_ffasn1c_RevokeEECerts(current, asn_contents);
      break;
    case kDot2CertCRLSeries_ScmsComponent:
    case kDot2CertCRLSeries_ScmsSpclComponent:
      ret = dot2_ffasn1c_RevokeSCCCertsUsingHashBasedCRL(current, asn_contents);
      break;
    default:
      Log(kDot2LogLevel_Event, "Not revoke certs using CRL contents - not supported crl_series %u\n", crl_series);
  }
  return ret;
}


/**
 * @brief CrlContents를 처리한다.
 * @param[in] current 현재시각
 * @param[in] crl_contents 처리할 CRL contents 바이트열
 * @param[in] crl_contents_size 처리할 CRL contents 바이트열의 길이
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ProcessCRLContents(Dot2Time32 current, const uint8_t *contents, size_t contents_size)
{
  int ret;
  Log(kDot2LogLevel_Event, "Process %zu-bytes CRL contents\n", contents_size);

  /*
   * CRL contents를 디코딩한다.
   */
  dot2CrlContents *asn_contents = NULL;
  ASN1Error err;
  asn1_ssize_t decoded_size = asn1_oer_decode((void **)&asn_contents,
                                              asn1_type_dot2CrlContents,
                                              contents,
                                              contents_size,
                                              &err);
  if (decoded_size < 0) {
    Err("Fail to process CRL contents - asn1_oer_decode() failed\n");
    return -kDot2Result_ASN1_DecodeCRL;
  }

  /*
   * CRL contents가 유효한지 확인한다.
   */
  if (dot2_ffasn1c_CheckCRLContentsValid(current, asn_contents) == false) {
    Log(kDot2LogLevel_Event, "CRL contents is not valid now\n");
    ret = -kDot2Result_CRL_InvalidPeriod;
    goto err;
  }

  /*
   * CRL contents를 이용하여 인증서를 폐지한다.
   */
  ret = dot2_ffasn1c_RevokeCertsUsingCRLContents(current, asn_contents);

err:
  asn1_free_value(asn1_type_dot2CrlContents, asn_contents);
  return ret;
}


/**
 * @brief SecuredCRL 내 signer 필드를 처리한다.
 * @param[in] asn_crl SecuredCrl 디코딩 정보
 * @param[in] h8 서명자 H8값이 저장될 버퍼 (8 이상의 길이를 가져야 한다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * signer 필드에 digest 정보가 들어 있으면, 해당 H8 값을 반환한다.
 * signer 필드에 인증서(들)이 들어 있으면, 첫번째 인증서를 SCC 인증서정보 저장소에 저장하고 H8 값을 계산하여 반환한다.
 */
static int dot2_ffasn1c_ProcessSecuredCRLSigner(dot2SecuredCrl *asn_crl, uint8_t *h8)
{
  int ret = -kDot2Result_CRL_InvalidSignerId;
  if (asn_crl->content.u.signedData.signer.choice == dot2SignerIdentifier_digest) {
    if ((asn_crl->content.u.signedData.signer.u.digest.buf) &&
        (asn_crl->content.u.signedData.signer.u.digest.len == 8)) {
      memcpy(h8, asn_crl->content.u.signedData.signer.u.digest.buf, 8);
      ret = kDot2Result_Success;
    }
  } else if (asn_crl->content.u.signedData.signer.choice == dot2SignerIdentifier_certificate) {
    if ((asn_crl->content.u.signedData.signer.u.certificate.count >= 1) &&
        (asn_crl->content.u.signedData.signer.u.certificate.tab)) {
      dot2Certificate *asn_signer = asn_crl->content.u.signedData.signer.u.certificate.tab;
      Dot2CertSize signer_size;
      uint8_t *signer = dot2_ffasn1c_EncodeCertificate((const dot2Certificate *)asn_signer, &signer_size);
      if (signer) {
        int err;
        dot2_AddSCCCert(signer, signer_size, &err);
        struct Dot2SHA256 signer_h;
        SHA256(signer, signer_size, signer_h.octs);
        memcpy(h8, DOT2_GET_SHA256_H8(signer_h.octs), 8);
        ret = kDot2Result_Success;
        free(signer);
      } else {
        Err("Fail to get securedCRL signer H8 - dot2_ffasn1c_EncodeCertificate() failed\n");
      }
    }
  }
  return ret;
}


/**
 * @brief SecuredCRL 을 검증한다 (서명을 검증한다)
 * @param[in] asn_crl SecuredCrl 디코딩 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_VerifySecuredCRL(dot2SecuredCrl *asn_crl)
{
  Log(kDot2LogLevel_Event, "Verify SecuredCrl\n");

  /*
   * CRL에 서명한 서명자 정보를 처리하고 서명자 H8 값을 획득한다.
   */
  uint8_t signer_id[8];
  int ret = dot2_ffasn1c_ProcessSecuredCRLSigner(asn_crl, signer_id);
  if (ret < 0) {
    Err("Fail to verify SecuredCrl - dot2_ffasn1c_ProcessSecuredCRLSigner() failed\n");
    return ret;
  }

  /*
   * 서명자 ID에 해당되는 SCC 인증서정보 엔트리를 탐색한다.
   */
  struct Dot2SCCCertInfoEntry *signer_entry = dot2_FindSCCCertWithHashedID8(signer_id);
  if (signer_entry == NULL) {
    Err("Fail to verify SecuredCRL - no SCC info in table\n");
    return -kDot2Result_NoSignerIdCertInTable;
  }

  /*
   * CRL 내에서 서명정보를 추출한다.
   */
  struct Dot2Signature sign;
  ret = dot2_ffasn1c_ParseSignature((dot2Signature *)&(asn_crl->content.u.signedData.signature), &sign);
  if (ret < 0) {
    Err("Fail to verify SecuredCrl - dot2_ffasn1c_ParseSignature() failed\n");
    return ret;
  }

  /*
   * CRL의 ToBeSignedData 필드를 인코딩한다 -> 서명검증연산의 입력으로 사용된다.
   */
  size_t tbs_size;
  uint8_t *tbs = dot2_ffasn1c_EncodeToBeSignedData(&(asn_crl->content.u.signedData.tbsData), &tbs_size);
  if (tbs == NULL) {
    Err("Fail to verify SecuredCrl - dot2_ffasn1c_EncodeToBeSignedData() failed\n");
    return -kDot2Result_ASN1_EncodeToBeSignedForSignature;
  }

  /*
   * 서명을 검증한다.
   */
  ret = dot2_ossl_VerifySignature_1(tbs,
                                    tbs_size,
                                    &(signer_entry->cert_h),
                                    signer_entry->contents.eck_verify_pub_key,
                                    &sign);
  free(tbs);
  return ret;
}


/**
 * @brief SecuredCrl을 처리한다.
 * @param[in] current 현재 시각
 * @param[in] asn_crl SecuredCrl 디코딩 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ProcessSecuredCRL(Dot2Time32 current, dot2SecuredCrl *asn_crl)
{
  Log(kDot2LogLevel_Event, "Process SecuredCrl\n");

  /*
   * 데이터 유효성을 체크한다.
   */
  if ((asn_crl->content.choice != dot2Ieee1609Dot2Content_signedData) ||
      (asn_crl->content.u.signedData.tbsData.payload.data_option == false) ||
      (asn_crl->content.u.signedData.tbsData.payload.data == NULL)) {
    Err("Fail to process SecuredCrl - invalid CRL\n");
    return -kDot2Result_CRL_InvalidContents;
  }

  /*
   * 서명을 검증한다.
   */
  int ret = dot2_ffasn1c_VerifySecuredCRL(asn_crl);
  if (ret < 0) {
    return ret;
  }

  /*
   * CrlContents들을 처리한다.
   */
  uint8_t *crl_contents;
  size_t crl_contents_size;
  dot2Ieee1609Dot2Data *inner_data = asn_crl->content.u.signedData.tbsData.payload.data;
  if ((inner_data->content.choice == dot2Ieee1609Dot2Content_unsecuredData) &&
      (inner_data->content.u.unsecuredData.buf) &&
      (inner_data->content.u.unsecuredData.len)) {
    crl_contents = inner_data->content.u.unsecuredData.buf;
    crl_contents_size = inner_data->content.u.unsecuredData.len;
    ret = dot2_ffasn1c_ProcessCRLContents(current, crl_contents, crl_contents_size);
    if (ret < 0) {
      return ret;
    }
  }
  return kDot2Result_Success;
}


/**
 * @brief SecuredCrlSeries를 처리한다.
 * @param[in] current 현재시각
 * @param[in] asn_sec_crl_series SecuredCrlSeries 디코딩 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_ProcessSecuredCRLSeries(Dot2Time32 current, dot2CompositeCrl_1 *asn_sec_crl_series)
{
  Log(kDot2LogLevel_Event, "Process securedCrlSeries\n");

  /*
   * 각 SecuredCRL들을 처리한다.
   */
  int ret;
  dot2SecuredCrl *asn_sec_crl;
  for (size_t i = 0; i < asn_sec_crl_series->count; i++) {
    asn_sec_crl = asn_sec_crl_series->tab + i;
    if (asn_sec_crl) {
      ret = dot2_ffasn1c_ProcessSecuredCRL(current, asn_sec_crl);
      if (ret < 0) {
        return ret;
      }
    }
  }
  return kDot2Result_Success;
}


/**
 * @brief CRL을 처리한다.
 * @param[in] crl CRL 바이트열
 * @param[in] crl_size CRL 바이트열의 길이
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ProcessCRL(const uint8_t *crl, Dot2CRLSize crl_size)
{
  int ret;
  Log(kDot2LogLevel_Event, "Process %zu-bytes CRL\n", crl_size);

  /*
   * 현재 시각을 구한다.
   */
  Dot2Time32 current = dot2_GetCurrentTime32();

  /*
   * CRL을 디코딩한다. CRL은 CompositeCrl 형식을 가진다.
   */
  dot2CompositeCrl *asn_crl = NULL;
  ASN1Error err1;
  asn1_ssize_t decoded_size = asn1_oer_decode((void **)&asn_crl, asn1_type_dot2CompositeCrl, crl, crl_size, &err1);
  if (decoded_size < 0) {
    Err("Fail to process CRL - asn1_oer_decode() failed\n");
    return -kDot2Result_ASN1_DecodeCRL;
  }

  /*
   * CRL 내 SecuredCrlSeries를 처리한다.
   */
  ret = dot2_ffasn1c_ProcessSecuredCRLSeries(current, &(asn_crl->securedCrlSeries));

  /*
   * CRL 내 RootCA 폐기정보를 처리한다 - 지원하지 않는다.
   */

  /*
   * CRL 내 Elector 폐기정보를 처리한다 - 지원하지 않는다.
   */

  asn1_free_value(asn1_type_dot2CompositeCrl, asn_crl);
  return ret;
}
