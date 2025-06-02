/** 
 * @file
 * @brief dot2 라이브러리 사용 기능을 구현한 파일
 * @date 2020-06-03
 * @author gyun
 */

// 시스템 헤더 파일
#include <dirent.h>

// 라이브러리 헤더 파일
#if defined(_LTEV2X_HAL_)
#include "dot2-2016/dot2.h"
#else
#include "dot2/dot2.h"
#endif

// 유틸리티 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief 특정 디렉토리에 저장되어 있는 모든 CMHF 파일들을 dot2 라이브러리에 로딩한다.
 * @param[in] dir_path CMHF 파일들이 저장된 디렉토리 경로 (상대경로, 절대경로 모두 가능)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int TCIA2023_LoadCMHFFiles(const char *dir_path)
{
  Log(kTCIA3LogLevel_Init, "Load CMHF files in %s\n", dir_path);

  /*
   * 디렉토리를 연다.
   */
  DIR *dir;
  struct dirent *ent;
  dir = opendir(dir_path);
  if (dir == NULL) {
    Err("Fail to load CMHF files in %s - opendir() failed : %m\n", dir_path);
    return -1;
  }

  /*
   * CMHF 파일의 경로가 저장될 버퍼를 할당한다.
   */
  size_t file_path_size = strlen(dir_path) + MAXLINE;
  char *file_path = (char *)calloc(1, file_path_size);
  if (file_path == NULL) {
    Err("Fail to load CMHF files - calloc() failed : %m\n");
    closedir(dir);
    return -1;
  }

  /*
   * 디렉토리 내 모든 CMHF 파일을 import하여 등록한다.
   */
  unsigned int add_cnt = 0;
  int ret;
  while ((ent = readdir(dir)) != NULL)
  {
    // 파일의 경로를 구한다. (입력된 디렉터리명과 탐색된 파일명의 결합)
    memset(file_path, 0, file_path_size);
    strcpy(file_path, dir_path);
    *(file_path + strlen(dir_path)) = '/';
    strcat(file_path, ent->d_name);

    Log(kTCIA3LogLevel_DetailedEvent, "Load CMHF file(%s)\n", file_path);

    // CMHF를 등록한다.
    ret = Dot2_LoadCMHFFile(file_path);
    if (ret < 0) {
      Err("Fail to load CMHF file(%s) - Dot2_LoadCMHFFile() failed: %d\n", file_path, ret);
      continue;
    }
    Log(kTCIA3LogLevel_DetailedEvent, "Success to load CMHF file\n");
    add_cnt++;
  }
  free(file_path);
  closedir(dir);

  Log(kTCIA3LogLevel_Init, "Sucess to load %u CMHF files\n", add_cnt);
  return 0;
}


/**
 * @brief 보안 관련 정보를 초기화한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_InitSecurity(void)
{
  int ret;
  Log(kTCIA3LogLevel_Init, "Initialize security\n");

  strncpy(g_tcia_mib.security.cmhf_dir, g_tcia_mib.input_params.cmhf_dir, sizeof(g_tcia_mib.security.cmhf_dir));
  strncpy(g_tcia_mib.security.rca_cert_file, g_tcia_mib.input_params.rca_cert_file, sizeof(g_tcia_mib.security.rca_cert_file));
  strncpy(g_tcia_mib.security.ica_cert_file, g_tcia_mib.input_params.ica_cert_file, sizeof(g_tcia_mib.security.ica_cert_file));
  strncpy(g_tcia_mib.security.pca_cert_file, g_tcia_mib.input_params.pca_cert_file, sizeof(g_tcia_mib.security.pca_cert_file));

  /*
   * 상위인증서들의 정보를 등록한다.
   */
  ret = Dot2_LoadSCCCertFile(g_tcia_mib.security.rca_cert_file);
  if (ret < 0) {
    Err("Fail to add RCA cert - Dot2_LoadSCCCertFile() failed: %d\n", ret);
    return -1;
  }
  ret = Dot2_LoadSCCCertFile(g_tcia_mib.security.ica_cert_file);
  if (ret < 0) {
    Err("Fail to add ICA cert - Dot2_LoadSCCCertFile() failed: %d\n", ret);
    return -1;
  }
  ret = Dot2_LoadSCCCertFile(g_tcia_mib.security.pca_cert_file);
  if (ret < 0) {
    Err("Fail to add PCA cert - Dot2_LoadSCCCertFile() failed: %d\n", ret);
    return -1;
  }

  /*
   * 서명 생성을 위한 CMHF를 등록한다. 본 어플리케이션에서는 psid=32, 38, 135만 사용된다.
   */
  ret = TCIA2023_LoadCMHFFiles(g_tcia_mib.security.cmhf_dir);
  if (ret < 0) {
    return -1;
  }

  /*
   * psid=135(WSA)용 Security profile을 등록한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 135;
  profile.tx.gen_time_hdr = true;
  profile.tx.gen_location_hdr = true;
  profile.tx.exp_time_hdr = true;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  /*
   * psid=32(BSM)용 Security profile을 등록한다.
   */
  profile.psid = 32;
  profile.tx.gen_time_hdr = true;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 450 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.rx.verify_data = true;
  profile.tx.interval = 100; // 100msec 주기로 송신
  profile.rx.relevance_check.replay = g_tcia_mib.input_params.bsm_replay;             // 기본값: false
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 30000000ULL; // 30sec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  /*
   * psid=127(Dot2 TEST)용 Security profile을 등록한다.
   */
  profile.psid = 127;
  profile.tx.gen_time_hdr = true;
  profile.tx.gen_location_hdr = true;
  profile.tx.exp_time_hdr = true;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  /*
   * psid=16511(Dot2 TEST)용 Security profile을 등록한다.
   */
  profile.psid = 16511;
  profile.tx.gen_time_hdr = true;
  profile.tx.gen_location_hdr = true;
  profile.tx.exp_time_hdr = true;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  /*
   * psid=2113663(Dot2 TEST)용 Security profile을 등록한다.
   */
  profile.psid = 2113663;
  profile.tx.gen_time_hdr = true;
  profile.tx.gen_location_hdr = true;
  profile.tx.exp_time_hdr = true;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  /*
   * psid=270549119(Dot2 TEST)용 Security profile을 등록한다.
   */
  profile.psid = 270549119;
  profile.tx.gen_time_hdr = true;
  profile.tx.gen_location_hdr = true;
  profile.tx.exp_time_hdr = true;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  /*
   * psid=130(SPAT)용 Security profile을 등록한다.
   */
  profile.psid = 130;
  profile.tx.gen_time_hdr = true;
  profile.tx.gen_location_hdr = true;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  /*
   * psid=131(TIM)용 Security profile을 등록한다.
   */
  profile.psid = 131;
  profile.tx.gen_time_hdr = true;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = true;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  /*
   * psid=2113686(SRM)용 Security profile을 등록한다.
   */
  profile.psid = 2113686;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  /*
   * psid=2113685(SSM)용 Security profile을 등록한다.
   */
  profile.psid = 2113685;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  Log(kTCIA3LogLevel_Init, "Success to initialize security\n");
  return 0;
}


/**
 * @brief Dot2_ProccessSPDU() 호출 결과를 전달 받는 콜백함수. dot2 라이브러리에서 호출된다.
 * @param[in] result 처리결과
 * @param[in] priv 패킷파싱데이터
 */
void TCIA2023_ProcessSPDUCallback(Dot2ResultCode result, void *priv)
{
  uint8_t ind_pkt[TCI_MSG_MAX_SIZE];
  int ind_pkt_size, ret;
  Dot3Latitude tx_lat = kDot3Latitude_Unavailable;
  Dot3Longitude tx_lon = kDot3Longitude_Unavailable;
  Dot3Elevation tx_elev = kDot3Elevation_Unavailable;

  struct V2XPacketParseData *parsed = (struct V2XPacketParseData *)priv;
  struct Dot2SPDUParseData *dot2_parsed = &(parsed->spdu);

  Cvcoctci2023SecurityResultCode result_code;
  if (result != kDot2Result_Success) {
    Err("Fail to process SPDU. result is %d\n", result);
    result_code = kCvcoctci2023SecurityResultCode_SpduCryptoVerificationFailure;
    goto indication;
  }

  /*
   * 로그 출력
   */
  Log(kTCIA3LogLevel_DetailedEvent, "Success to process SPDU\n");
  Log(kTCIA3LogLevel_DetailedEvent, "  content_type: %d, psid: %u, signer_id_type: %d, payload_size: %u\n",
      dot2_parsed->content_type, dot2_parsed->signed_data.psid, dot2_parsed->signed_data.signer_id_type,
      parsed->ssdu_size);
  if (dot2_parsed->signed_data.gen_time_present) {
    Log(kTCIA3LogLevel_DetailedEvent, "  gen_time: %llu\n", dot2_parsed->signed_data.gen_time);
  }
  if (dot2_parsed->signed_data.expiry_time_present) {
    Log(kTCIA3LogLevel_DetailedEvent, "  expiry_time: %llu\n", dot2_parsed->signed_data.expiry_time);
  }
  if (dot2_parsed->signed_data.gen_location_present) {
    Log(kTCIA3LogLevel_DetailedEvent, "  gen_lat: %d, gen_lon: %d, gen_elev: %u\n",
        dot2_parsed->signed_data.gen_location.lat, dot2_parsed->signed_data.gen_location.lon,
        dot2_parsed->signed_data.gen_location.elev);
  }
  TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, parsed->ssdu, parsed->ssdu_size);


  result_code = kCvcoctci2023SecurityResultCode_Success;
  if (dot2_parsed->signed_data.gen_location_present) {
    tx_lat = dot2_parsed->signed_data.gen_location.lat;
    tx_lon = dot2_parsed->signed_data.gen_location.lon;
    tx_elev = dot2_parsed->signed_data.gen_location.elev;
  }

  /*
   * WSA를 처리한다 - 채널 접속 및 WRA 정보 적용이 수행된다.
   */
  struct Dot3ParseWSAParams wsa_params;
  if (parsed->mac_wsm.wsm.psid == kDot3PSID_WSA) {
    memset(&wsa_params, 0, sizeof(wsa_params));
    Dot3WSAType wsa_type;
    if (dot2_parsed->content_type == kDot2Content_UnsecuredData) {
      wsa_type = kDot3WSAType_Unsecured;
    } else {
      wsa_type = kDot3WSAType_Secured;
    }
    ret = TCIA2023_ProcessRxWSA(parsed->rx_params.if_idx,
                             parsed->ssdu,
                             parsed->ssdu_size,
                             parsed->mac_wsm.mac.src_mac_addr,
                             wsa_type,
                             parsed->rx_params.rcpi,
                             tx_lat,
                             tx_lon,
                             tx_elev,
                             &wsa_params);
    if (ret < 0) {
      goto out;
    }
  }
    /*
     * 그 외의 메시지는 현 시점의 표준적합성 시험 기준으로는 딱히 처리할 필요가 없다 (Indication만 전달하면 된다)
     */
  else {}

indication:
  /*
   * Indication 메시지를 생성하여 전송한다.
   */
  ind_pkt_size = TCIA2023_ConstructIndication(parsed->pkt,
                                          parsed->pkt_size,
                                          parsed->wsm,
                                          parsed->wsm_size,
                                          &(parsed->rx_params),
                                          &(parsed->mac_wsm),
                                          &wsa_params,
                                          result_code,
                                          ind_pkt,
                                          sizeof(ind_pkt));
  if (ind_pkt_size > 0) {
    TCIA2023_SendTCIMessagePacket(ind_pkt, ind_pkt_size);
  }

out:
  V2X_FreePacketParseData(parsed);
}
