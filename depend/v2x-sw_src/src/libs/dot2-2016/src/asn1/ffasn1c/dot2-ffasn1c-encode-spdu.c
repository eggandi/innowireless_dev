/** 
  * @file 
  * @brief SPDU 인코딩 관련 구현
  * @date 2022-08-06 
  * @author gyun 
  */



// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-ffasn1c-inline.h"


/**
 * @brief Unsecured 형식의 Ieee1609Dot2Data asn.1 정보구조체를 채운다.
 * @param[in] payload 수납될 페이로드
 * @param[in] payload_size 수납될 페이로드의 길이
 * @param[out] dot2_data 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int
dot2_ffasn1c_FillUnsecuredIeee1609Dot2Data(const uint8_t *payload, Dot2SPDUSize payload_size, dot2Ieee1609Dot2Data *to)
{
  to->protocolVersion = DOT2_PROTOCOL_VERSION;
  to->content.choice = dot2Ieee1609Dot2Content_unsecuredData;
  return dot2_ffasn1c_FillASN1String(payload, payload_size, &(to->content.u.unsecuredData));
}


/**
 * @brief Ieee1609Dot2Data를 인코딩한다.
 * @param[in] dot2_data 인코딩할 Ieee1609Dot2Data asn.1 정보 구조체
 * @param[out] encoded_size 인코딩된 데이터의 길이가 저장될 변수 포인터
 * @return 인코딩된 데이터 포인터
 * @retval NULL: 실패
 */
static inline uint8_t * dot2_ffasn1c_EncodeIeee1609Dot2Data(dot2Ieee1609Dot2Data *dot2_data, size_t *encoded_size)
{
  uint8_t *buf, *ret = NULL;
  *encoded_size = (int)asn1_oer_encode(&buf, asn1_type_dot2Ieee1609Dot2Data, dot2_data);
  if ((*encoded_size > 0) &&
      (buf != NULL)) {
    ret = buf;
  }
  return ret;
}


/**
 * @brief ffasn1c 인코더를 이용하여 unsecured Ieee1609Dot2Data 를 인코딩한다.
 * @param[in] payload 수납될 페이로드
 * @param[in] payload_size 수납될 페이로드의 길이
 * @param[out] spdu 인코딩된 SPDU 바이트열이 저장될 버퍼 포인터
 * @return 인코딩된 SPDU 바이트열의 길이
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL
dot2_ffasn1c_EncodeUnsecuredIeee1609Dot2Data(const uint8_t *payload, Dot2SPDUSize payload_size, uint8_t **spdu)
{
  Log(kDot2LogLevel_Event, "Encode Ieee1609Dot2Data(unsecured)\n");

  *spdu = NULL;

  /*
   * 인코딩 파라미터를 설정한다.
   */
  dot2Ieee1609Dot2Data *dot2_data = (dot2Ieee1609Dot2Data *)asn1_mallocz_value(asn1_type_dot2Ieee1609Dot2Data);
  if (!dot2_data) {
    return -kDot2Result_NoMemory;
  }
  int ret = dot2_ffasn1c_FillUnsecuredIeee1609Dot2Data(payload, payload_size, dot2_data);
  if (ret < 0) {
    Err("Fail to encode Ieee1609Dot2Data(unsecured) - dot2_ffasn1c_FillUnsecuredIeee1609Dot2Data() failed\n");
    goto out;
  }

  /*
   * 인코딩한다.
   */
  size_t encoded_size;
  uint8_t *encoded = dot2_ffasn1c_EncodeIeee1609Dot2Data(dot2_data, &encoded_size);
  if (!encoded) {
    Err("Fail to encode Ieee1609Dot2Data(unsecured) - dot2_ffasn1c_EncodeIeee1609Dot2Data() failed\n");
    ret = -kDot2Result_SPDU_EncodeSPDU;
    goto out;
  }

  Log(kDot2LogLevel_Event, "Success to encode %zu-bytes Ieee1609Dot2Data(unsecured)\n", encoded_size);
  ret = (int)encoded_size;
  *spdu = encoded;

out:
  asn1_free_value(asn1_type_dot2Ieee1609Dot2Data, dot2_data);
  return ret;
}


/**
 * @brief SignedDataPayload asn.1 정보구조체를 채운다.
 * @param[in] payload 수납될 페이로드
 * @param[in] payload_size 수납될 페이로드의 길이
 * @param[out] to 정보를 채울 SignedDataPayload 필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillSignedDataPayload(
  const uint8_t *payload,
  size_t payload_size,
  struct dot2SignedDataPayload *to)
{
  int ret = kDot2Result_Success;
  Log(kDot2LogLevel_Event, "Fill SignedDataPayload\n");
  if ((payload != NULL) && (payload_size > 0)) {
    ret = -kDot2Result_NoMemory;
    to->data = asn1_mallocz_value(asn1_type_dot2Ieee1609Dot2Data);
    if (to->data) {
      to->data_option = true;
      to->data->protocolVersion = DOT2_PROTOCOL_VERSION;
      to->data->content.choice = dot2Ieee1609Dot2Content_unsecuredData;
      ret = dot2_ffasn1c_FillASN1String(payload, payload_size, &(to->data->content.u.unsecuredData));
    }
  }
  return ret;
}


/**
 * @brief ToBeSignedData asn.1 정보구조체를 채운다.
 * @param[in] payload 수납될 페이로드
 * @param[in] payload_size 수납될 페이로드의 길이
 * @param[in] psid 수납될 PSID
 * @param[in] gen_time_hdr 헤더에 생성시각정보를 수납할지 여부
 * @param[in] gen_time 수납될 생성시각정보
 * @param[in] exp_time_hdr 헤더에 만기시각정보를 수납할지 여부
 * @param[in] exp_time 수납될 만기시각정보
 * @param[in] gen_location_hdr 헤더에 생성지점정보를 수납할지 여부
 * @param[in] gen_location 수납될 생성지점정보
 * @param[out] to 정보를 채울 ToBeSignedData asn.1 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillToBeSignedData(
  const uint8_t *payload,
  size_t payload_size,
  Dot2PSID psid,
  bool gen_time_hdr,
  Dot2Time64 gen_time,
  bool exp_time_hdr,
  Dot2Time64 exp_time,
  bool gen_location_hdr,
  const struct Dot2ThreeDLocation *gen_location,
  dot2ToBeSignedData *to)
{
  Log(kDot2LogLevel_Event, "Fill signedData.tbsData\n");

  /*
   * payload 필드를 채운다.
   */
  int ret = dot2_ffasn1c_FillSignedDataPayload(payload, payload_size, &(to->payload));
  if (ret < 0) {
    Err("Fail to fill signedData.tbsData - dot2_ffasn1c_FillSignedDataPayload() failed\n");
    return ret;
  }

  /*
   * headerInfo 필드를 채운다.
   * 현재 psid, generationTime, expiryTime, generationLocation 필드를 지원한다.
   */
  dot2HeaderInfo *asn1_hdr_info = &(to->headerInfo);
  ret = asn1_integer_set_ui(&(asn1_hdr_info->psid), (uint32_t)psid);
  if (ret < 0) {
    Err("Fail to fill signedData.tbsData - asn1_integer_set_ui(psid: %u) failed\n", psid);
    return -kDot2Result_SPDU_EncodePSID;
  }
  if (gen_time_hdr == true) {
    asn1_hdr_info->generationTime_option = true;
    ret = asn1_integer_set_ui64(&(asn1_hdr_info->generationTime), gen_time);
    if (ret < 0) {
      Err("Fail to fill signedData.tbsData - asn1_integer_set_ui64(gen_time: "PRIu64") failed\n", gen_time);
      return -kDot2Result_SPDU_EncodeGenTime;
    }
  }
  if (exp_time_hdr == true) {
    asn1_hdr_info->expiryTime_option = true;
    ret = asn1_integer_set_ui64(&(asn1_hdr_info->expiryTime), exp_time);
    if (ret < 0) {
      Err("Fail to fill signedData.tbsData - asn1_integer_set_ui64(exp_time: "PRIu64") failed\n", exp_time);
      return -kDot2Result_SPDU_EncodeExpTime;
    }
  }
  if (gen_location_hdr == true) {
    asn1_hdr_info->generationLocation_option = true;
    asn1_hdr_info->generationLocation.latitude = gen_location->lat;
    asn1_hdr_info->generationLocation.longitude = gen_location->lon;
    asn1_hdr_info->generationLocation.elevation = gen_location->elev;
  }

  Log(kDot2LogLevel_Event, "Success to fill signedData.tbsData\n");
  return kDot2Result_Success;
}


/**
 * @brief SignerIdentifier asn.1 정보구조체를 다이제스트로 채운다.
 * @param[in] signer_h8 서명자인증서 다이제스트
 * @param[out] to 정보를 채울 SignerIdentifier asn.1 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_FillSignerIdentifier_Digest(const uint8_t *signer_h8, dot2SignerIdentifier *to)
{
  Log(kDot2LogLevel_Event, "Fill signedData.signer(Digest)\n");
  to->choice = dot2SignerIdentifier_digest;
  if (dot2_ffasn1c_FillASN1String(signer_h8, 8, &(to->u.digest)) < 0) {
    return -kDot2Result_NoMemory;
  }
  return kDot2Result_Success;
}


/**
 * @brief SignerIdentifier asn.1 정보구조체를 인증서로 채운다.
 * @param[in] asn1_signer 서명자인증서 asn.1 정보
 * @param[out] to 정보를 채울 SignerIdentifier asn.1 정보구조체 포인터
 */
static inline void dot2_ffasn1c_FillSignerIdentifier_Certificate(dot2Certificate *asn1_signer, dot2SignerIdentifier *to)
{
  Log(kDot2LogLevel_Event, "Fill signedData.signer(Certificate)\n");
  to->choice = dot2SignerIdentifier_certificate;
  to->u.certificate.count = 1;
  to->u.certificate.tab = asn1_clone_value(asn1_type_dot2Certificate, asn1_signer);
}


/**
 * @brief SignerIdentifier asn.1 정보구조체를 채운다.
 * @param[in] signer_id_type 서명자인증서 식별자 유형 (Certificate or Digest)
 * @param[in] signer_h8 서명자인증서 다이제스트 (signer_id_type = Digest인 경우에 사용됨)
 * @param[in] asn1_signer 서명자인증서 asn.1 정보 (signer_id_type = Certificate인 경우에 사용됨)
 * @param[out] to 정보를 채울 SignerIdentifier asn.1 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_FillSignerIdentifier(
  Dot2SignerIdType signer_id_type,
  const uint8_t *signer_h8,
  dot2Certificate *asn1_signer,
  dot2SignerIdentifier *to)
{
  int ret;
  if (signer_id_type == kDot2SignerId_Digest) {
    ret = dot2_ffasn1c_FillSignerIdentifier_Digest(signer_h8, to);
  } else {
    dot2_ffasn1c_FillSignerIdentifier_Certificate(asn1_signer, to);
    ret = kDot2Result_Success;
  }
  return ret;
}


/**
 * @brief Signature asn.1 정보구조체를 채운다.
 * @param[in] sign 서명
 * @param[out] to 정보를 채울 Signature asn.1 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillSignature(struct Dot2Signature *sign, dot2Signature *to)
{
  Log(kDot2LogLevel_Event, "Fill signature\n");

  int ret;

  /*
   * 서명 R을 채운다.
   */
  to->choice = dot2Signature_ecdsaNistP256Signature;
  dot2EccP256CurvePoint *asn1_r = &(to->u.ecdsaNistP256Signature.rSig);
  struct Dot2ECPoint *R_r = &(sign->R_r);
  Dot2ECPointForm form = R_r->u.point.form;
  switch (form) {
    case kDot2ECPointForm_X_only:
      asn1_r->choice = dot2EccP256CurvePoint_x_only;
      ret = dot2_ffasn1c_FillASN1String(R_r->u.point.u.point, DOT2_EC_256_KEY_LEN, &(asn1_r->u.x_only));
      break;
    case kDot2ECPointForm_Compressed_y_0:
      asn1_r->choice = dot2EccP256CurvePoint_compressed_y_0;
      ret = dot2_ffasn1c_FillASN1String(R_r->u.point.u.point, DOT2_EC_256_KEY_LEN, &(asn1_r->u.compressed_y_0));
      break;
    case kDot2ECPointForm_Compressed_y_1:
      asn1_r->choice = dot2EccP256CurvePoint_compressed_y_1;
      ret = dot2_ffasn1c_FillASN1String(R_r->u.point.u.point, DOT2_EC_256_KEY_LEN, &(asn1_r->u.compressed_y_1));
      break;
    case kDot2ECPointForm_Uncompressed:
      asn1_r->choice = dot2EccP256CurvePoint_uncompressedP256;
      ret = dot2_ffasn1c_FillASN1String(R_r->u.point.u.point, DOT2_EC_256_KEY_LEN, &(asn1_r->u.uncompressedP256.x));
      if (ret == kDot2Result_Success) {
        ret = dot2_ffasn1c_FillASN1String(R_r->u.point.u.xy.y, DOT2_EC_256_KEY_LEN, &(asn1_r->u.uncompressedP256.y));
      }
      break;
    default:
      Err("Fail to fill signature - invalid r_sig type %u\n", form);
      ret = -kDot2Result_SPDU_InvalidSignatureType;
  }
  if (ret < 0) {
    return ret;
  }

  /*
   * 서명 s를 채운다.
   */
  ret = dot2_ffasn1c_FillASN1String(sign->s, DOT2_EC_256_KEY_LEN, &(to->u.ecdsaNistP256Signature.sSig));
  if (ret < 0) {
    return ret;
  }

  Log(kDot2LogLevel_Event, "Success to fill signature\n");
  return kDot2Result_Success;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 SignedData를 수납한 Ieee1609Dot2Data를 인코딩한다.
 * @param[in] payload 수납될 페이로드
 * @param[in] payload_size 수납될 페이로드의 길이
 * @param[in] psid 수납될 PSID
 * @param[in] gen_time_hdr 헤더에 생성시각정보를 수납할지 여부
 * @param[in] gen_time 수납될 생성시각정보
 * @param[in] exp_time_hdr 헤더에 만기시각정보를 수납할지 여부
 * @param[in] exp_time 수납될 만기시각정보
 * @param[in] gen_location_hdr 헤더에 생성지점정보를 수납할지 여부
 * @param[in] gen_location 수납될 생성지점정보
 * @param[in] signer_id_type 서명자인증서 식별자 유형 (Certificate or Digest)
 * @param[in] signer_h 서명자인증서 해시
 * @param[in] eck_priv_key 서명 생성시 사용되는 개인키
 * @param[in] asn1_signer 서명자인증서 asn.1 정보 (동적할당된 정보여야 하며, 본 함수 내에서 사용 후 free() 된다)
 * @param[in] sign_form 서명 형식
 * @param[out] spdu 생성된 SPDU가 저장될 버퍼 포인터
 * @return 생성된 SPDU의 길이
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_EncodeSignedIeee1609Dot2Data(
  const uint8_t *payload,
  size_t payload_size,
  Dot2PSID psid,
  bool gen_time_hdr,
  Dot2Time64 gen_time,
  bool exp_time_hdr,
  Dot2Time64 exp_time,
  bool gen_location_hdr,
  const struct Dot2ThreeDLocation *gen_location,
  Dot2SignerIdType signer_id_type,
  const struct Dot2SHA256 *signer_h,
  EC_KEY *eck_priv_key,
  dot2Certificate *asn1_signer,
  Dot2ECPointForm sign_form,
  uint8_t **spdu)
{
  Log(kDot2LogLevel_Event, "Encode Ieee1609Dot2Data(signed)\n");

  uint8_t *tbs = NULL;
  *spdu = NULL;

  /*
   * asn1 인코딩을 위한 정보구조체 메모리를 할당한다.
   */
  dot2Ieee1609Dot2Data *asn1_dot2_data = (dot2Ieee1609Dot2Data *)asn1_mallocz_value(asn1_type_dot2Ieee1609Dot2Data);
  if (asn1_dot2_data == NULL) {
    return -kDot2Result_NoMemory;
  }

  /*
   * Ieee1609Dot2Data 기본 필드, signedData.hashId 필드를 채운다.
   */
  asn1_dot2_data->protocolVersion = DOT2_PROTOCOL_VERSION;
  asn1_dot2_data->content.choice = dot2Ieee1609Dot2Content_signedData;
  dot2SignedData *asn1_signed_data = &(asn1_dot2_data->content.u.signedData);
  asn1_signed_data->hashId = dot2HashAlgorithm_sha256;

  /*
   * signedData.tbsData 필드를 채운다.
   */
  int ret = dot2_ffasn1c_FillToBeSignedData(payload,
                                            payload_size,
                                            psid,
                                            gen_time_hdr,
                                            gen_time,
                                            exp_time_hdr,
                                            exp_time,
                                            gen_location_hdr,
                                            gen_location,
                                            &(asn1_signed_data->tbsData));
  if (ret < 0) {
    goto out;
  }

  /*
   * signedData.signer 필드를 채운다.
   */
  const uint8_t *signer_h8 = DOT2_GET_SHA256_H8(signer_h->octs);
  ret = dot2_ffasn1c_FillSignerIdentifier(signer_id_type, signer_h8, asn1_signer, &(asn1_signed_data->signer));
  if (ret < 0) {
    goto out;
  }

  /*
   * 서명 생성을 위해 tbsData 필드를 인코딩한다.
   */
  size_t tbs_size;
  asn1_ssize_t size = asn1_oer_encode(&tbs, asn1_type_dot2ToBeSignedData, &(asn1_signed_data->tbsData));
  if ((size < 0) ||
      (tbs == NULL)) {
    Err("Fail to encode Ieee1609Dot2Data(signed) - dot2_ffasn1c_EncodeToBeSignedData() failed\n");
    ret = -kDot2Result_SPDU_EncodeToBeSignedData;
    goto out;
  }
  tbs_size = (size_t)size;

  /*
   * ToBeSignedData 필드에 대한 서명을 생성한다.
   */
  struct Dot2Signature sign;
  ret = dot2_ossl_GenerateSignature(sign_form, tbs, tbs_size, signer_h, eck_priv_key, &sign);
  if (ret < 0) {
    Err("Fail to encode Ieee1609Dot2Data(signed) - dot2_ossl_GenerateSignature() failed\n");
    ret = -kDot2Result_SPDU_GenerateSign;
    goto out;
  }

  /*
   * sigedData.signature 필드를 채운다.
   */
  ret = dot2_ffasn1c_FillSignature(&sign, &(asn1_signed_data->signature));
  if (ret < 0) {
    goto out;
  }

  /*
   * Ieee1609Dot2Data 메시지를 인코딩한다.
   */
  size_t encoded_size;
  uint8_t *encoded = dot2_ffasn1c_EncodeIeee1609Dot2Data(asn1_dot2_data, &encoded_size);
  if (encoded == NULL) {
    Err("Fail to encode Ieee1609Dot2Data(signed) - dot2_ffasn1c_EncodeIeee1609Dot2Data() failed\n");
    ret = -kDot2Result_SPDU_EncodeSPDU;
    goto out;
  }

  *spdu = encoded;
  ret = (int)encoded_size;
  Log(kDot2LogLevel_Event, "Success to encode %d-bytes Ieee1609Dot2Data(signed)\n", ret);
//  if (asn1_signed_data->signer.choice == dot2SignerIdentifier_digest) {
//    asn1_signed_data->signer.u.digest.len = 0;
//    free(asn1_signed_data->signer.u.digest.buf);
//    //asn1_signed_data->signer.u.digest.buf = NULL;
//  } else if (asn1_signed_data->signer.choice == dot2SignerIdentifier_certificate) {
//    asn1_signed_data->signer.u.certificate.tab = NULL;
//    asn1_signed_data->signer.u.certificate.count = 0;
//  }

out:
  if (tbs) { free(tbs); }
  asn1_free_value(asn1_type_dot2Ieee1609Dot2Data, asn1_dot2_data);
  return ret;
}
