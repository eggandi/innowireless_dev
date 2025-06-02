/** 
  * @file 
  * @brief 등록인증서 발급요청문 관련 구현
  * @date 2022-05-01 
  * @author gyun 
  */


// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "asn1/ffasn1c/dot2-ffasn1c-inline.h"
#include "lcm/dot2-lcm.h"


/**
 * @brief 등록인증서 발급요청문 내 ValidRegion 내용을 채운다.
 * @param[in] params 등록인증서 발급요청문의 생성을 위한 파라미터
 * @param[out] asn1_region 정보를 채울 asn.1 정보 구조체
 *
 * KCAC.V2X.CERTPROF V2X 인증서 프로파일 규격 v1.1(2020.11) p.40/43에 따라 내용을 채운다.
 */
static void
dot2_ffasn1c_FillECRequest_ValidRegion(struct Dot2ECRequestConstructParams *params, dot2GeographicRegion *asn1_region)
{
  Log(kDot2LogLevel_Event, "Fill ECRequest.ValidRegion\n");
  asn1_region->choice = dot2GeographicRegion_identifiedRegion;
  asn1_region->u.identifiedRegion.count = params->valid_region.region_num;
  asn1_region->u.identifiedRegion.tab = asn1_mallocz(sizeof(dot2IdentifiedRegion) * asn1_region->u.identifiedRegion.count);
  if (asn1_region->u.identifiedRegion.tab) {
    for (size_t cnt = 0; cnt < asn1_region->u.identifiedRegion.count; cnt++) {
      dot2IdentifiedRegion *r = asn1_region->u.identifiedRegion.tab + cnt;
      r->choice = dot2IdentifiedRegion_countryOnly;
      r->u.countryOnly = (dot2CountryOnly)(params->valid_region.region[cnt]);
    }
  }
}


/**
 * @brief 등록인증서 발급요청문 내 Permissions 내용을 채운다.
 * @param[in] params 등록인증서 발급요청문의 생성을 위한 파라미터
 * @param[out] asn1_perms 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * KCAC.V2X.CERTPROF V2X 인증서 프로파일 규격 v1.1(2020.11) p.40/43에 따라 내용을 채운다.
 */
static int dot2_ffasn1c_FillECRequest_Permissions(
  struct Dot2ECRequestConstructParams *params,
  dot2SequenceOfPsidGroupPermissions *asn1_perms)
{
  Log(kDot2LogLevel_Event, "Fill ECRequest.Permissions\n");
  int ret = kDot2Result_Success;
  asn1_perms->count = 1; // 현재 국내에서 사용되는 등록인증서 내용 참조 -> 1개 존재
  asn1_perms->tab = asn1_mallocz(sizeof(dot2PsidGroupPermissions));
  if (asn1_perms->tab) {
    /*
     * subjectPermissions 정보를 채운다.
     *  - 현재 국내에서 사용되는 등록인증서 내용 참조 -> explicit 유형 사용
     */
    asn1_perms->tab->subjectPermissions.choice = dot2SubjectPermissions_Explicit;
    dot2SequenceOfPsidSspRange *e = &(asn1_perms->tab->subjectPermissions.u.Explicit);
    e->count = (size_t)(params->permissions.num);
    e->tab = asn1_mallocz(sizeof(dot2PsidSspRange) * e->count);
    if (e->tab) {
      for (size_t cnt = 0; cnt < e->count; cnt++) {
        dot2PsidSspRange *r = e->tab + cnt;
        // 현재 국내에서 사용되는 등록인증서 내용 참조 -> psid만 채우고 sspRange는 채우지 않는다.
        ret = asn1_integer_set_ui(&(r->psid), (uint32_t)(params->permissions.psid[cnt]));
        if (ret < 0) {
          return -kDot2Result_ASN1_SetInteger;
        }
      }
    }

    /*
     * minChainLength, chainLengthRange, eeType 정보를 채운다.
     *  - minChainLength: 현재 국내에서 사용되는 등록인증서 내용 참조 -> 0으로 채운다.
     *  - chainLengthRange: 현재 국내에서 사용되는 등록인증서 내용 참조 -> 0으로 채운다.
     *  - eeType: application(b7)으로 채운다. (등록인증서 내 들어갈 권한의 대상은 application이므로)
     *     -> eeType=application(b7)은 DEFAULT 값과 동일하므로, 수납하지 않는다
     *       (ffasn1 제약사항: BIT STRING, OCTET STRING 유형의 정보가 DEFAULT 값과 같으면, 직접 제외해 주어야 한다)
     */
    ret = asn1_integer_set_ui(&(asn1_perms->tab->minChainLength), 0);
    if (ret < 0) {
      return -kDot2Result_ASN1_SetInteger;
    }
    ret = asn1_integer_set_ui(&(asn1_perms->tab->chainLengthRange), 0);
    if (ret < 0) {
      return -kDot2Result_ASN1_SetInteger;
    }
  }
  return ret;
}


/**
 * @brief 등록인증서 발급요청문 내 VerifyKeyIndicator 내용을 채운다.
 * @param[in] init_key_pair 초기 개인키/공개키 정보
 * @param[out] asn1 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillECRequest_VerifyKeyIndicator(
  struct Dot2ECKeyPair *init_key_pair,
  dot2VerificationKeyIndicator *asn1)
{
  int ret;
  Log(kDot2LogLevel_Event, "Fill ECRequest.VerifyKeyIndicator\n");
  asn1->choice = dot2VerificationKeyIndicator_verificationKey;
  asn1->u.verificationKey.choice = dot2PublicVerificationKey_ecdsaNistP256;
  uint8_t *pub_key_x = init_key_pair->octs.pub_key.u.point.u.xy.x;
  uint8_t *pub_key_y = init_key_pair->octs.pub_key.u.point.u.xy.y;
  if (pub_key_y[DOT2_EC_256_KEY_LEN - 1] & 1) {
    asn1->u.verificationKey.u.ecdsaNistP256.choice = dot2EccP256CurvePoint_compressed_y_1;
    ASN1String *to = &(asn1->u.verificationKey.u.ecdsaNistP256.u.compressed_y_1);
    ret = dot2_ffasn1c_FillASN1String(pub_key_x, DOT2_EC_256_KEY_LEN, to);
  } else {
    asn1->u.verificationKey.u.ecdsaNistP256.choice = dot2EccP256CurvePoint_compressed_y_0;
    ASN1String *to = &(asn1->u.verificationKey.u.ecdsaNistP256.u.compressed_y_0);
    ret = dot2_ffasn1c_FillASN1String(pub_key_x, DOT2_EC_256_KEY_LEN, to);
  }
  return ret;
}


/**
 * @brief 등록인증서 발급요청문 내 ScopedCertificateRequest 필드를 채운다.
 * @param[in] params 등록인증서 발급요청문의 생성을 위한 파라미터
 * @param[in] init_key_pair 초기 개인키/공개키 정보
 * @param[out] asn1_cr 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillECRequest_ScopedCertificateRequest(
  struct Dot2ECRequestConstructParams *params,
  struct Dot2ECKeyPair *init_key_pair,
  dot2ScopedCertificateRequest *asn1_cr)
{
  Log(kDot2LogLevel_Event, "Fill ECRequest.ScopedCertificateRequest\n");

  asn1_cr->version = KDot2ScmsPDUVersion_SCMS;
  asn1_cr->content.choice = dot2ScmsPDU_1_eca_ee;
  asn1_cr->content.u.eca_ee.choice = dot2EcaEndEntityInterfacePDU_eeEcaCertRequest;

  dot2EeEcaCertRequest *asn1_ecr = &(asn1_cr->content.u.eca_ee.u.eeEcaCertRequest);
  asn1_ecr->version = KDot2ScmsPDUVersion_SCMS;
  asn1_ecr->currentTime = params->time;

  /*
   * KCAC.V2X.CERTPROF V2X 인증서 프로파일 규격 v1.1(2020.11) p.40/43에 따라 ToBeSignedCertificate 내용을 채운다.
   * - id: 빈문자열("") 사용
   * - crlSeries: 등록인증서용 crlSeries 사용
   * - region: identifiedRegion 사용
   * - certRequestPermissions: PSID만 들어 있는 PsidSsp 사용
   * - verifyKeyIndicator: 초기 공개키 사용
   * - 미사용 정보: cracaId, assuranceLevel, appPermissions, certIssuePermissions, canRequestRollover, encryptionKey
   */
  dot2ToBeSignedCertificate *asn1_tbs = &(asn1_ecr->tbsData);
  asn1_tbs->id.choice = dot2CertificateId_name;
  asn1_tbs->id.u.name.len = 0;
  uint8_t craca_id[3] = { 0x00, 0x00, 0x00 };
  int ret = dot2_ffasn1c_FillASN1String(craca_id, sizeof(craca_id), &(asn1_tbs->cracaId));
  if (ret < 0) {
    return ret;
  }
  asn1_tbs->crlSeries = kDot2CrlSeries_EeEnrollmentCrlSeries;
  asn1_tbs->validityPeriod.start = params->valid_period.start;
  asn1_tbs->validityPeriod.duration.choice = (dot2Duration_choice)(params->valid_period.duration.type);
  asn1_tbs->validityPeriod.duration.u.hours = (dot2Uint16)params->valid_period.duration.duration; // 모든 choice가 동일한 변수유형이므로 대표로 hours에 입력한다.
  if (params->valid_region.region_num) {
    asn1_tbs->region_option = true;
    dot2_ffasn1c_FillECRequest_ValidRegion(params, &(asn1_tbs->region));
  }
  if (params->permissions.num) {
    asn1_tbs->certRequestPermissions_option = true;
    ret = dot2_ffasn1c_FillECRequest_Permissions(params, &(asn1_tbs->certRequestPermissions));
    if (ret < 0) {
      return ret;
    }
  }
  return dot2_ffasn1c_FillECRequest_VerifyKeyIndicator(init_key_pair, &(asn1_tbs->verifyKeyIndicator));
}


/**
 * @brief 등록인증서 발급요청문 내 Signer 내용을 채운다.
 * @param[out] asn1_signer 정보를 채울 asn.1 정보 구조체
 */
static inline void dot2_ffasn1c_FillECREquest_Signer(dot2SignerIdentifier *asn1_signer)
{
  asn1_signer->choice = dot2SignerIdentifier_self;
}


/**
 * @brief 등록인증서 발급요청문 내 Signature 필드를 채운다.
 * @param[in] init_key_pair 초기 개인키/공개키 정보
 * @param[in] asn1_tbs 서명 입력에 사용되는 ToBeSigned 필드 asn.1 정보 구조체
 * @param[out] asn1_sign 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillECRequest_Signature(
  struct Dot2ECKeyPair *init_key_pair,
  dot2ScopedCertificateRequest *asn1_tbs,
  dot2Signature *asn1_sign)
{
  Log(kDot2LogLevel_Event, "Fill ECRequest.Signature\n");

  /*
   * 서명 입력에 사용될 ToBeSigned 필드를 인코딩한다.
   */
  uint8_t *encoded;
  asn1_ssize_t encoded_size = asn1_oer_encode(&encoded, asn1_type_dot2ScopedCertificateRequest, asn1_tbs);
  if ((!encoded) ||
      (encoded_size < 0)) {
    return -kDot2Result_ASN1_EncodeToBeSignedForSignature;
  }

  /*
   * 서명을 생성한다.
   */
  struct Dot2Signature sign;
  Dot2ECPointForm form = kDot2ECPointForm_Compressed;
  int ret = dot2_ossl_GenerateSignature(form, encoded, (size_t)encoded_size, NULL, init_key_pair->eck, &sign);
  free(encoded);
  if (ret < 0) {
    return ret;
  }

  /*
   * rSig 필드를 채운다.
   */
  asn1_sign->choice = dot2Signature_ecdsaNistP256Signature;
  uint8_t *R_y = sign.R_r.u.point.u.xy.y;
  if (R_y[DOT2_EC_256_KEY_LEN - 1] & 1) {
    asn1_sign->u.ecdsaNistP256Signature.rSig.choice = dot2EccP256CurvePoint_compressed_y_1;
    ASN1String *to = &(asn1_sign->u.ecdsaNistP256Signature.rSig.u.compressed_y_1);
    ret = dot2_ffasn1c_FillASN1String(sign.R_r.u.point.u.xy.x, DOT2_EC_256_KEY_LEN, to);
  } else {
    asn1_sign->u.ecdsaNistP256Signature.rSig.choice = dot2EccP256CurvePoint_compressed_y_0;
    ASN1String *to = &(asn1_sign->u.ecdsaNistP256Signature.rSig.u.compressed_y_0);
    ret = dot2_ffasn1c_FillASN1String(sign.R_r.u.point.u.xy.x, DOT2_EC_256_KEY_LEN, to);
  }
  if (ret < 0) {
    return ret;
  }

  /*
   * sSig 필드를 채운다.
   */
  ASN1String *to = &(asn1_sign->u.ecdsaNistP256Signature.sSig);
  return dot2_ffasn1c_FillASN1String(sign.s, DOT2_EC_256_KEY_LEN, to);
}


/**
 * @brief 등록인증서 발급요청문 내 SignedCertificateRequest 필드를 Opaque 형식으로 채운다.
 * @param[in] params 등록인증서 발급요청문의 생성을 위한 파라미터
 * @param[in] init_key_pair 초기 개인키/공개키 정보
 * @param[out] asn1_cr_opaque 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillECRequest_SignedCertificateRequest(
  struct Dot2ECRequestConstructParams *params,
  struct Dot2ECKeyPair *init_key_pair,
  dot2Opaque *asn1_cr_opaque)
{
  Log(kDot2LogLevel_Event, "Fill ECRequest.SignedCertificateRequest\n");

  int ret = -kDot2Result_NoMemory;
  uint8_t *encoded = NULL;
  dot2SignedCertificateRequest *asn1_cr;
  asn1_cr = (dot2SignedCertificateRequest *)asn1_mallocz_value(asn1_type_dot2SignedCertificateRequest);
  if (asn1_cr) {

    // signedCertificateRequest.hashId 내용을 채운다.
    asn1_cr->hashId = dot2HashAlgorithm_sha256;

    // signedCertificateRequest.scopedCertificateRequest 내용을 채운다.
    ret = dot2_ffasn1c_FillECRequest_ScopedCertificateRequest(params, init_key_pair, &(asn1_cr->tbsRequest));
    if (ret < 0) {
      goto out;
    }

    // signedCertificateRequest.signer(서명자) 정보를 채운다.
    dot2_ffasn1c_FillECREquest_Signer(&(asn1_cr->signer));

    // signedCertificateRequest.signature(서명) 정보를 채운다.
    ret = dot2_ffasn1c_FillECRequest_Signature(init_key_pair, &(asn1_cr->tbsRequest), &(asn1_cr->signature));
    if (ret < 0) {
      goto out;
    }

    // signedCertificateRequest를 OER 인코딩하여 opaque 형식으로 정보를 채워 반환한다.
    ret = -kDot2Result_ASN1_EncodeSignedCertificateRequest;
    asn1_ssize_t encoded_size = asn1_oer_encode(&encoded, asn1_type_dot2SignedCertificateRequest, asn1_cr);
    if (encoded &&
        (encoded_size > 0)) {
      asn1_cr_opaque->len = (size_t)encoded_size;
      asn1_cr_opaque->buf = encoded;
      ret = kDot2Result_Success;
    }
  }

out:
  if (asn1_cr) { asn1_free_value(asn1_type_dot2SignedCertificateRequest, asn1_cr); }
  return ret;
}


/**
 * @brief 등록인증서 발급요청문 PDU 내용을 채운다.
 * @param[in] params 등록인증서 발급요청문의 생성을 위한 파라미터
 * @param[in] init_key_pair 초기 개인키/공개키 정보
 * @param[out] asn1_ecr 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillECRequest(
  struct Dot2ECRequestConstructParams *params,
  struct Dot2ECKeyPair *init_key_pair,
  dot2SignedEeEnrollmentCertRequest *asn1_ecr)
{
  asn1_ecr->protocolVersion = DOT2_PROTOCOL_VERSION;
  asn1_ecr->content.choice = dot2Ieee1609Dot2Content_signedCertificateRequest;

  /*
   * PDU 내 signedCertificateRequest 필드를 채운다.
   */
  dot2Opaque *asn1_cr = &(asn1_ecr->content.u.signedCertificateRequest);
  return dot2_ffasn1c_FillECRequest_SignedCertificateRequest(params, init_key_pair, asn1_cr);
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 등록인증서 발급요청문을 생성한다.
 * @param[in] params 등록인증서 발급요청문의 생성을 위한 파라미터
 * @param[in] init_key_pair 초기 개인키/공개키 정보
 * @param[out] ret 인코딩 결과가 저장될 변수 포인터. 성공 시 인코딩된 발급요청문의 길이, 실패 시 음수(-Dot2ResultCode)가 저장된다.
 * @return OER 인코딩된 등록인증서 발급요청문 바이트열. 동적할당된 정보이므로 사용 후 free()해 주어야 한다.
 */
uint8_t INTERNAL * dot2_ffasn1c_ConstructECRequest(
  struct Dot2ECRequestConstructParams *params,
  struct Dot2ECKeyPair *init_key_pair,
  int *ret)
{
  Log(kDot2LogLevel_Event, "Construct ECRequest\n");

  int ret1 = -kDot2Result_NoMemory;
  uint8_t *encoded = NULL;
  asn1_ssize_t encoded_size;

  /*
   * 등록인증서 발급요청문 정보를 채우고 OER 인코딩한다.
   */
  dot2SignedEeEnrollmentCertRequest *asn1_ecr_pdu = NULL;
  asn1_ecr_pdu = (dot2SignedEeEnrollmentCertRequest *)asn1_mallocz_value(asn1_type_dot2SignedEeEnrollmentCertRequest);
  if (asn1_ecr_pdu) {
    ret1 = dot2_ffasn1c_FillECRequest(params, init_key_pair, asn1_ecr_pdu);
    if (ret1 == kDot2Result_Success) {
      ret1 = -kDot2Result_ASN1_EncodeECRequest;
      encoded_size = asn1_oer_encode(&encoded, asn1_type_dot2SignedEeEnrollmentCertRequest, asn1_ecr_pdu);
      if (encoded &&
          (encoded_size > 0)) {
        ret1 = (int)encoded_size;
      }
    }
    asn1_free_value(asn1_type_dot2SignedEeEnrollmentCertRequest, asn1_ecr_pdu);
  }
  *ret = ret1;
  return encoded;
}
