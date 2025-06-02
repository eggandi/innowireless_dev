/** 
  * @file 
  * @brief SPDU 생성 기능을 구현한 파일
  * @date 2021-09-12 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "sec-profile/dot2-sec-profile-inline.h"
#include "spdu/dot2-spdu.h"
#include "spdu/dot2-spdu-inline.h"
#if defined(_FFASN1C_)
#include "dot2-ffasn1c.h"
#elif defined(_OBJASN1C_)
#include "dot2-objasn1c.h"
#else
#error "3rd party asn.1 library is not defined"
#endif


/**
 * @brief SPDU 생성을 위한 정보들을 가져온다.
 * @param[in] psid PSID
 * @param[in] gen_time SPDU 생성시점
 * @param[in] cmh_change CMH 변경 요청 여부
 * @param[in/out] signer_id_type 서명자 식별자 유형
 * @param[out] gen_time_hdr 헤더에 생성시각정보를 수납할지 여부가 반환될 변수 포인터
 * @param[out] exp_time_hdr 헤더에 만기시각정보를 수납할지 여부가 반환될 변수 포인터
 * @param[out] exp_time 만기시각정보가 반환될 변수 포인터
 * @param[out] gen_location_hdr 헤더에 생성지점정보를 수납할지 여부가 반환될 변수 포인터
 * @param[out] signer_h 서명자 해시가 반환될 구조체 포인터
 * @param[out] eck_priv_key 서명용 개인키가 반환될 구조체 포인터 (사용 후 free()해 주어야 한다)
 * @param[out] asn1_signer 서명자 asn.1 정보가 반환될 구조체 포인터 (사용 후 free()해 주어야 한다)
 *                         objasn1 사용시에는 복사되지 않고 참조포인터만 반환된다 (즉, 사용 후 free() 해서는 안된다)
 * @param[out] sign_form 생성될 서명의 형식이 반환될 변수 포인터
 * @param[out] cmh_expiry 현 시점에 CMH가 만기되었는지 여부 또는 다음번 서명생성주기에 CMH가 만기될지 여부가 반환될 변수 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_GetSPDUConstructInfo(
  Dot2PSID psid,
  Dot2Time64 gen_time,
  bool cmh_change,
  Dot2SignerIdType *signer_id_type,
  bool *gen_time_hdr,
  bool *exp_time_hdr,
  Dot2Time64 *exp_time,
  bool *gen_location_hdr,
  struct Dot2SHA256 *signer_h,
  EC_KEY **eck_priv_key,
  void **asn1_signer,
  Dot2ECPointForm *sign_form,
  bool *cmh_expiry)
{
  Log(kDot2LogLevel_Event, "Get SPDU construct info\n");

  /*
   * 요청된 PSID를 이용하여 서명 생성에 사용될 Security profile을 찾는다.
   */
  struct Dot2SecProfileEntry *sec_profile_entry = dot2_FindSecProfile(psid);
  if (sec_profile_entry == NULL) {
    Err("Fail to get SPDU construct info - no security profile for PSID(%u)\n", psid);
    return -kDot2Result_SPDU_NoSecProfile;
  }

  /*
   * 요청된 PSID를 이용하여 서명 생성에 사용될 CMH를 찾아서 필요 정보를 가져온다.
   *  - Rotate CMH의 경우, CMH 변경 요청 여부(cmh_change)에 따라 세트 내에서 사용되는 인증서도 변경된다.
   * 활성 CMH가 변경되는 경우, Security profile의 인증서 서명시점을 초기화하여, 이후 첫 서명이 인증서로 서명되도록 한다.
   */
  bool cmh_changed = false;
  unsigned int interval = sec_profile_entry->profile.tx.interval;
  int ret = dot2_GetAvailableCMHInfo(psid,
                                     gen_time,
                                     interval,
                                     cmh_change,
                                     signer_h,
                                     eck_priv_key,
                                     asn1_signer,
                                     &cmh_changed,
                                     cmh_expiry);
  if (ret < 0) {
    return ret;
  }
  if (cmh_changed == true) {
    sec_profile_entry->last_cert_sign_time = 0ULL;
  }

  /*
   * 서명에 사용될 SignerId를 Security profile에 따라 결정한다.
   *  - 인증서로 서명 요청 받았을 경우에는, 인증서 서명 시점만 업데이트한다. (다음번 인증서 서명 시점을 체크하기 위해)
   *  - 다이제스트로 서명 요청 받았을 경우에는, 아무 동작하지 않는다.
   *  - 지원되지 않는 SignerId는 API 파라미터 체크에서 이미 걸러졌다.
   */
  if (*signer_id_type == kDot2SignerId_Profile) {
    *signer_id_type = dot2_SelectSignerIdType(gen_time, sec_profile_entry);
  } else if (*signer_id_type == kDot2SignerId_Certificate) {
    dot2_UpdateSecProfile_LastCertSignTime(gen_time, sec_profile_entry);
  }

  /*
   * 필요정보를 반환한다.
   */
  *gen_time_hdr = sec_profile_entry->profile.tx.gen_time_hdr;
  *exp_time_hdr = sec_profile_entry->profile.tx.exp_time_hdr;
  *exp_time = gen_time + sec_profile_entry->profile.tx.spdu_lifetime;
  *gen_location_hdr = sec_profile_entry->profile.tx.gen_location_hdr;
  *sign_form = dot2_GetSecProfile_SignForm(sec_profile_entry);
  return kDot2Result_Success;
}


/**
 * @brief Signed SPDU를 생성한다.
 * @param[in] payload SPDU에 수납될 페이로드
 * @param[in] payload_size SPDU에 수납될 페이로드의 길이
 * @param[in] gen_time SPDU 생성시점
 * @param[in] signer_id_type 서명자 식별자 유형
 * @param[in] gen_location 생성지점 정보
 * @param[in] cmh_change CMH 변경 요청 여부
 * @param[out] spdu 생성된 SPDU가 반환될 버퍼 포인터
 * @param[out] cmh_expiry 현 시점에 CMH가 만기되었는지 여부 또는 다음번 서명생성주기에 CMH가 만기될지 여부가 반환될 변수 포인터
 * @return 생성된 SPDU의 길이
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ConstructSignedSPDU(
  const uint8_t *payload,
  Dot2SPDUSize payload_size,
  Dot2PSID psid,
  Dot2Time64 gen_time,
  Dot2SignerIdType signer_id_type,
  const struct Dot2ThreeDLocation *gen_location,
  bool cmh_change,
  uint8_t **spdu,
  bool *cmh_expiry)
{
  Log(kDot2LogLevel_Event, "Construct signed SPDU\n");
  Log(kDot2LogLevel_Event, "   psid: %u, gen_time: %"PRIu64", signer_id_type: %u(0:digest,1:cert,3:profile)\n",
      psid, gen_time, signer_id_type);
  Log(kDot2LogLevel_Event, "   lat: %d, lon: %d, elev: %u, cmh_change: %u(bool)\n",
      gen_location->lat, gen_location->lon, gen_location->elev, cmh_change);

  /*
   * SPDU 생성을 위해 필요한 정보들을 가져온다.
   */
  bool gen_time_hdr;
  bool exp_time_hdr;
  bool gen_location_hdr;
  Dot2Time64 exp_time;
  struct Dot2SHA256 signer_h;
  EC_KEY *eck_priv_key = NULL;
  void *asn1_signer = NULL;
  Dot2ECPointForm sign_form;
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  int ret = dot2_GetSPDUConstructInfo(psid,
                                      gen_time,
                                      cmh_change,
                                      &signer_id_type,
                                      &gen_time_hdr,
                                      &exp_time_hdr,
                                      &exp_time,
                                      &gen_location_hdr,
                                      &signer_h,
                                      &eck_priv_key,
                                      &asn1_signer,
                                      &sign_form,
                                      cmh_expiry);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
  if (ret < 0) {
    return ret;
  }

  /*
   * Ieee1609Dot2Data 패킷을 생성한다.
   */
#if defined(_FFASN1C_)
  ret = dot2_ffasn1c_EncodeSignedIeee1609Dot2Data(payload,
                                                  payload_size,
                                                  psid,
                                                  gen_time_hdr,
                                                  gen_time,
                                                  exp_time_hdr,
                                                  exp_time,
                                                  gen_location_hdr,
                                                  gen_location,
                                                  signer_id_type,
                                                  &signer_h,
                                                  eck_priv_key,
                                                  asn1_signer,
                                                  sign_form,
                                                  spdu);
  if (ret < 0) {
    Err("Fail to construct signed SPDU - dot2_ffasn1c_EncodeSignedIeee1609Dot2Data() failed\n");
  } else {
    Log(kDot2LogLevel_Event, "Success to construct %d-bytes signed SPDU\n", ret);
  }
  if (asn1_signer) {
    asn1_free_value(asn1_type_dot2Certificate, asn1_signer);
  }
#elif defined(_OBJASN1C_)
  ret = dot2_objasn1c_EncodeSignedIeee1609Dot2Data(payload,
                                                   payload_size,
                                                   psid,
                                                   gen_time_hdr,
                                                   gen_time,
                                                   exp_time_hdr,
                                                   exp_time,
                                                   gen_location_hdr,
                                                   gen_location,
                                                   signer_id_type,
                                                   &signer_h,
                                                   eck_priv_key,
                                                   asn1_signer,
                                                   sign_form,
                                                   spdu);
  if (ret < 0) {
    Err("Fail to construct signed SPDU - dot2_objasn1c_EncodeSignedIeee1609Dot2Data() failed\n");
  } else {
    Log(kDot2LogLevel_Event, "Success to construct %d-bytes signed SPDU\n", ret);
  }
#else
#error "3rd party asn.1 library is not defined"
#endif

  if (eck_priv_key) { EC_KEY_free(eck_priv_key); }
  return ret;
}
