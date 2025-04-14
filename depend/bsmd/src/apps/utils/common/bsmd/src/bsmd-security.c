/**
 * @file
 * @brief Security 기능 구현
 * @date 2022-09-17
 * @author gyun
 */


// 시스템 헤더 파일
#include <assert.h>
#include <dirent.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"

// 유틸리티 헤더 파일
#include "include/bsmd.h"


/**
 * @brief 특정 디렉토리에 저장되어 있는 모든 CMHF 파일들을 dot2 라이브러리에 로딩한다.
 * @param[in] dir_path CMHF 파일들이 저장된 디렉토리 경로 (상대경로, 절대경로 모두 가능)
 */
static void BSMD_LoadCMHFFiles(const char *dir_path)
{
  Log(kBSMDLogLevel_Event, "Load CMHF files in %s\n", dir_path);

  /*
   * 디렉토리를 연다.
   */
  DIR *dir;
  struct dirent *ent;
  dir = opendir(dir_path);
  assert(dir);

  /*
   * CMHF 파일의 경로가 저장될 버퍼를 할당한다.
   */
  size_t file_path_size = strlen(dir_path) + MAXLINE;
  char *file_path = (char *)calloc(1, file_path_size);
  assert(file_path);

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

    Log(kBSMDLogLevel_Event, "Load CMHF file(%s)\n", file_path);

    // CMHF를 등록한다.
    ret = Dot2_LoadCMHFFile(file_path);
    if (ret < 0) {
      Err("Fail to load CMHF file(%s) - Dot2_LoadCMHFFile() failed: %d\n", file_path, ret);
      continue;
    }
    Log(kBSMDLogLevel_Event, "Success to load CMHF file\n");
    add_cnt++;
  }
  free(file_path);
  closedir(dir);

  Log(kBSMDLogLevel_Event, "Sucess to load %u CMHF files\n", add_cnt);
}


/**
 * @brief 보안 관련 정보를 초기화한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int BSMD_InitSecurity(void)
{
  int ret;
  Log(kBSMDLogLevel_Event, "Initialize security\n");

  /*
   * 상위인증서들의 정보를 등록한다.
   */
  ret = Dot2_LoadSCCCertFile(RCA_FILE);
  if (ret < 0) {
    Err("Fail to add RCA cert - Dot2_LoadSCCCertFile() failed: %d\n", ret);
    return -1;
  }
  ret = Dot2_LoadSCCCertFile(ICA_FILE);
  if (ret < 0) {
    Err("Fail to add ICA cert - Dot2_LoadSCCCertFile() failed: %d\n", ret);
    return -1;
  }
  ret = Dot2_LoadSCCCertFile(PCA_FILE);
  if (ret < 0) {
    Err("Fail to add PCA cert - Dot2_LoadSCCCertFile() failed: %d\n", ret);
    return -1;
  }

  /*
   * 서명 생성을 위한 CMHF를 등록한다.
   */
  BSMD_LoadCMHFFiles(CMHF_DIR);

  /*
   * BSM용(psid=32) Security profile을 등록한다.
   */
  struct Dot2SecProfile profile;
  memset(&profile, 0, sizeof(profile));
  profile.psid = BSM_PSID;
  profile.tx.gen_time_hdr = true;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 450 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100; // 100msec 주기로 송신
  if (g_bsmd_mib.op == kBSMDOperation_TxOnly) {
    profile.rx.verify_data = false; // 수신 기능은 사용하지 않는다.
  } else {
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
  }
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    Err("Fail to register security profile - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  Log(kBSMDLogLevel_Event, "Success to initialize security\n");
  return 0;
}


/**
 * @brief Dot2_ProccessSPDU() 호출 결과를 전달 받는 콜백함수. dot2 라이브러리에서 호출된다.
 * @param[in] result 처리결과
 * @param[in] priv 패킷파싱데이터
 */
void BSMD_ProcessSPDUCallback(Dot2ResultCode result, void *priv)
{
  struct V2XPacketParseData *parsed = (struct V2XPacketParseData *)priv;

  /*
   * 서명 검증 실패
   */
  if (result != kDot2Result_Success) {
    Err("Fail to process SPDU. result is %d\n", result);
    goto out;
  }

  /*
   * BSM을 처리한다.
   */
  if (parsed->mac_wsm.wsm.psid == BSM_PSID) {
    Log(kBSMDLogLevel_Event, "BSM is received\n");
  }

out:
  V2X_FreePacketParseData(parsed);
}
