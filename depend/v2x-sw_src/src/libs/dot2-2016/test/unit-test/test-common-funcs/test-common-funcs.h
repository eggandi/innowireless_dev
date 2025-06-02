/** 
  * @file 
  * @brief 테스트에 공통으로 사용되는 기능/유형/형식 정의 파일
  * @date 2021-12-30 
  * @author gyun 
  */

#ifndef V2X_SW_TEST_COMMON_FUNCS_H
#define V2X_SW_TEST_COMMON_FUNCS_H


// 시스템 헤더 파일
#include <cstddef>
#include <cstdint>
#include <unistd.h>

// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/// 메시지 처리 콜백함수가 호출될 때까지 기다린다.(단위테스트를 수행하는 시스템의 성능에 따라 지연 값을 조절한다)
#define WAIT_MSG_PROCESS_CALLBACK usleep(10000)


/// 테스트시작시간을 전역변수에 저장한다.
#define SAVE_TEST_START_TIME \
  do {                           \
    clock_gettime(CLOCK_REALTIME, &g_test_start_ts); \
  } while(0)

/// 테스트종료 후 테스트시간이 변경될 때까지 기다린다.
#define WAIT_SYSTIME_RECOVERY \
  do { \
    struct timespec past_ts = g_test_start_ts;  \
    past_ts.tv_sec -= 1; \
    clock_settime(CLOCK_REALTIME, &past_ts); \
    system("ntpdate -d 203.248.240.140 >> /dev/null"); \
    struct timespec test_end_ts{}; \
    while(true) { \
      printf("Wait for the system time to recover\n"); \
      sleep(1); \
      clock_gettime(CLOCK_REALTIME, &test_end_ts); \
      if (test_end_ts.tv_sec > g_test_start_ts.tv_sec) { \
        break; \
      } \
    } \
  } while(0)

extern struct timespec g_test_start_ts;


/**
 * @brief ProcessSPDUCallback 함수로 전달되는 메시지 처리 결과가 저장되는 엔트리
 */
struct Dot2Test_ProcessSPDUCallbackEntry
{
  Dot2ResultCode result;
  struct V2XPacketParseData *parsed;
};


/**
 * @brief ProcessSPDUCallback 함수로 전달되는 메시지 처리 결과들이 저장되는 리스트
 */
struct Dot2Test_ProcessSPDUCallbackList
{
#define MAX_ENTRY_NUM (150000)
  unsigned int cnt;
  struct Dot2Test_ProcessSPDUCallbackEntry entry[MAX_ENTRY_NUM];
};

extern struct Dot2Test_ProcessSPDUCallbackList g_callbacks;


// test-common-funcs.cc
bool Dot2Test_CompareOctets(const void *octs1, const void *octs2, size_t len);
int Dot2Test_ConvertHexStrToOctets(const char *hex_str, uint8_t *octs);
void Dot2Test_PrintOcts(const char *desc, const void *octs, size_t len);
size_t Dot2Test_GetVariableLengthRandomOcts(uint8_t *buf, size_t buf_size);
void Dot2Test_GetFixedLengthRandomOcts(uint8_t *buf, size_t buf_size);

// test-common-funcs-scc-cert.cc
void Dot2Test_AddSCCCerts();
void Dot2Test_InitTestVector_RCACertContents(struct Dot2SCCCertContents *contents);
void Dot2Test_InitTestVector_ICACertContents(struct Dot2SCCCertContents *contents);
void Dot2Test_InitTestVector_PCACertContents(struct Dot2SCCCertContents *contents);
void Dot2Test_InitTestVector_ECACertContents(struct Dot2SCCCertContents *contents);
void Dot2Test_InitTestVector_RACertContents(struct Dot2SCCCertContents *contents);

// test-common-funcs-sec-profile.cc
void Dot2Test_SetSecProfile(struct Dot2SecProfile *profile);
void Dot2Test_AddWSASecurityProfile();
void Dot2Test_AddBSMSecurityProfile();
void Dot2Test_AddPVDSecurityProfile();

// test-common-funcs-ca-cert.cc
void Dot2Test_AddCACerts();
void Dot2Test_InitSampleRCACertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleICACertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleECACertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSamplePCACertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleRACertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_CompareRCACertInfo(struct Dot2CertEntry *rca_entry, uint8_t *sample_rca, Dot2CertSize sample_rca_size, struct Dot2CertInfo *sample_rca_info);
void Dot2Test_CompareICACertInfo(struct Dot2CertEntry *ica_entry, uint8_t *sample_ica, Dot2CertSize sample_ica_size, struct Dot2CertInfo *sample_ica_info);
void Dot2Test_CompareECACertInfo(struct Dot2CertEntry *eca_entry, uint8_t *sample_eca, Dot2CertSize sample_eca_size, struct Dot2CertInfo *sample_eca_info);
void Dot2Test_ComparePCACertInfo(struct Dot2CertEntry *pca_entry, uint8_t *sample_pca, Dot2CertSize sample_pca_size, struct Dot2CertInfo *sample_pca_info);
void Dot2Test_CompareRACertInfo(struct Dot2CertEntry *ra_entry, uint8_t *sample_ra, Dot2CertSize sample_ra_size, struct Dot2CertInfo *sample_ra_info);

// test-common-funcs-rse-cert.cc
void Dot2Test_InitSampleRse0CertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_CheckRegisteredRSE0AppCert(bool verified);
void Dot2Test_CheckNoRSE0AppCert();

// test-common-funcs-obu-cert.cc
void Dot2Test_InitSampleObu10A0CertInfo(struct Dot2CertInfo *cert_info);

// test-common-funcs-spdu.cc
void Dot2Test_ProcessSPDUCallback(Dot2ResultCode result, void *priv);
void Dot2Test_InitProcessSPDUCallbackList();
void Dot2Test_FlushProcessSPDUCallbackList();

// test-common-funcs-cmh.cc
void Dot2Test_AddRSECMHFs();
void Dot2Test_AddOBUCMHFs();

#if 0


// test-common-funcs.cc
bool Dot2Test_CompareOctets(const void *octs1, const void *octs2, size_t len);
void Dot2Test_PrintOcts(const char *desc, const void *octs, size_t len);

// test-common-funcs-ca-cert.cc
void Dot2Test_AddCACerts();
void Dot2Test_InitSampleRCACertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleICACertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleECACertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSamplePCACertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleRACertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_CompareRCACertInfo(struct Dot2CertEntry *rca_entry, uint8_t *sample_rca, Dot2CertSize sample_rca_size, struct Dot2CertInfo *sample_rca_info);
void Dot2Test_CompareICACertInfo(struct Dot2CertEntry *ica_entry, uint8_t *sample_ica, Dot2CertSize sample_ica_size, struct Dot2CertInfo *sample_ica_info);
void Dot2Test_CompareECACertInfo(struct Dot2CertEntry *eca_entry, uint8_t *sample_eca, Dot2CertSize sample_eca_size, struct Dot2CertInfo *sample_eca_info);
void Dot2Test_ComparePCACertInfo(struct Dot2CertEntry *pca_entry, uint8_t *sample_pca, Dot2CertSize sample_pca_size, struct Dot2CertInfo *sample_pca_info);
void Dot2Test_CompareRACertInfo(struct Dot2CertEntry *ra_entry, uint8_t *sample_ra, Dot2CertSize sample_ra_size, struct Dot2CertInfo *sample_ra_info);

// test-common-funcs-rse-cert.cc
void Dot2Test_InitSampleRse0CertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_CheckRegisteredRSE0AppCert(bool verified);
void Dot2Test_CheckNoRSE0AppCert();

// test-common-funcs-obu-cert.cc
void Dot2Test_InitSampleObu10A0CertInfo(struct Dot2CertInfo *cert_info);

// test-common-funcs-other-cert.cc
void Dot2Test_InitSampleMinRectangularRegionCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleMaxRectangularRegionCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleMaxCountryOnlyIdentifiedRegionCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleUsecDurationCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleMsecDurationCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleSecDurationCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleMinuteDurationCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleSixtyHoursDurationCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleMaxAppPermsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleShortestOpaqueSspAppPermsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleLongestOpaqueSspAppPermsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleShortestBitmapSspAppPermsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleLongestBitmapSspAppPermsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleMaxCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleTooManyCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleMaxPsidSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleTooManyPsidSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleMaxOpaqueSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleLongestOpaqueSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleShortestBitmapSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleLongestBitmapSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info);
void Dot2Test_InitSampleMaxCertRequestPermissionsCertInfo(struct Dot2CertInfo *cert_info);

// test-common-funcs-cmh.cc
void Dot2Test_AddRSECMHFs();
void Dot2Test_AddOBUCMHFs();
void Dot2Test_InitSampleRse0CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleRse1CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleRse2CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleRse3CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleRse4CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A0CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A1CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A2CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A3CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A4CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A5CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A6CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A7CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A8CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A9CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10AACMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10ABCMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10ACCMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10ADCMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10AECMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10AFCMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A10CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A11CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A12CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10A13CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10B0CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10C0CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10D0CMHInfo(struct Dot2CMHInfo *cmh_info);
void Dot2Test_InitSampleObu10E0CMHInfo(struct Dot2CMHInfo *cmh_info);


#endif


#endif //V2X_SW_TEST_COMMON_FUNCS_H
