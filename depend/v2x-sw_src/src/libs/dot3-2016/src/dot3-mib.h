/**
 * @file
 * @brief Management Information Base (MIB) 정의 헤더 파일
 * @date 2019-08-16
 * @author gyun
 */


#ifndef LIBDOT3_DOT3_MIB_H
#define LIBDOT3_DOT3_MIB_H


// 시스템 헤더 파일
#include <pthread.h>

// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"


/**
 * @brief PSR(Provider Service Request) 테이블 엔트리
 */
struct Dot3PSRTableEntry
{
  struct Dot3PSR psr; ///< Provider Service Request 정보
  unsigned int option_cnt; ///< Provider Service Request 내 존재하는 옵션필드 개수
  struct Dot3PCITableEntry *pci_entry; ///< 서비스채널과 연관된 Provider Channel Info 참조
  TAILQ_ENTRY(Dot3PSRTableEntry) entries; ///< 테이블 내 엔트리간 연결 변수
};
TAILQ_HEAD(Dot3PSRTableEntryHead, Dot3PSRTableEntry);


/**
 * @brief PSR(Provider Service Request) 테이블
 */
struct Dot3PSRTable
{
  Dot3PSRNum num; ///< 테이블 내 PSR 엔트리 개수
  struct Dot3PSRTableEntryHead head; ///< 테이블 내 PSR 엔트리 리스트
};



/**
 * @brief UAS(User Service Request) 테이블 엔트리
 */
struct Dot3USRTableEntry
{
  struct Dot3USR usr; ///< User Service Request 정보
  TAILQ_ENTRY(Dot3USRTableEntry) entries; ///< 테이블 내 엔트리간 연결 변수
};
TAILQ_HEAD(Dot3USRTableEntryHead, Dot3USRTableEntry);


/**
 * @brief USR(User Service Request) 테이블
 */
struct Dot3USRTable
{
  Dot3USRNum num; ///< 테이블 내 USR 엔트리 개수
  struct Dot3USRTableEntryHead head; ///< 테이블 내 PSR 엔트리 리스트
};


/**
 * @brief PCI(Provider Channel Info) 테이블 엔트리
 *
 * dot3 라이브러리 초기화 시, V2X 주파수 대역의 각 채널에 대한 초기 테이블이 생성되며, 이는 WSA의 channel info 필드에 수납된다. \n
 * chan_access 정보는 초기화 시 설정되지 않고, WSA 생성 시에 업데이트 된다.
 */
struct Dot3PCITableEntry
{
  struct Dot3PCI pci; ///< PCI 정보
  unsigned int option_cnt; ///< PCI 내 존재하는 옵션필드 개수
  TAILQ_ENTRY(Dot3PCITableEntry) entries; ///< 테이블 내 엔트리간 연결 변수
};
TAILQ_HEAD(Dot3PCITableEntryHead, Dot3PCITableEntry);


/**
 * @brief PCI(Provider Channel Info) 테이블
 */
struct Dot3PCITable
{
  Dot3PCINum num; ///< 테이블 내 PCI 엔트리 개수
  struct Dot3PCITableEntryHead head; ///< 테이블 내 PCI 엔트리 리스트
};


/**
 * @brief WSR(WSM Service Request) 테이블 엔트리
 */
struct Dot3WSRTableEntry
{
  struct Dot3WSR wsr; ///< WSR 정보
  TAILQ_ENTRY(Dot3WSRTableEntry) entries; ///< 테이블 내 엔트리간 연결 변수
};
TAILQ_HEAD(Dot3WSRTableEntryHead, Dot3WSRTableEntry);


/**
 * @brief WSR(WSM Service Request) 테이블
 */
struct Dot3WSRTable
{
  pthread_mutex_t mtx; ///< WSR 정보 동기화를 위한 뮤텍스
  Dot3WSRNum num; ///< 테이블 내 WSR 엔트리 개수
  struct Dot3WSRTableEntryHead head; ///< 테이블 내 WSR 엔트리 리스트
};


/**
 * @brief UAS(User Available Service) 테이블 엔트리
 */
struct Dot3UASTableEntry
{
  struct Dot3UAS uas; ///< UAS 정보
  uint8_t *wsa; ///< 수신된 WSA 패킷데이터
  size_t wsa_size; ///< 수신된 WSA 패킷데이터의 길이
  bool check_rx_cnt; ///< 정보유효성을 판단하기 위해 수신카운트가 사용되는지 여부
  double rx_cnt_in_mgmt_timer_interval; ///< UAS 관리타이머 1주기 동안 수신된 WSA 개수
  double unit_interval_cnt; ///< 100msec 주기 발생 횟수
  time_t expiry; ///< 만기시각(초단위)
  TAILQ_ENTRY(Dot3UASTableEntry) entries; ///< 테이블 내 엔트리간 연결 변수
};
TAILQ_HEAD(Dot3UASTableEntryHead, Dot3UASTableEntry);


/**
 * @brief UAS(User Available Service) 테이블
 */
struct Dot3UASTable
{
  bool mgmt_running; ///< UAS가 관리 기능이 동작 중인지 여부
  timer_t timer; ///< UAS 정보 관리 타이머
  Dot3UASManagementInterval timer_interval; ///< UAS 정보 관리 타이머 주기

  Dot3UASNum num; ///< 테이블 내 UAS 엔트리 개수
  struct Dot3UASTableEntryHead head; ///< 테이블 내 UAS 엔트리 리스트
};


/**
 * @brief Provider 관련 정보
 */
struct Dot3ProviderInfo
{
  pthread_mutex_t mtx; ///< Provider 관련정보 동기화를 위한 뮤텍스
  struct Dot3PSRTable psr_table; ///< PSR 테이블
  struct Dot3PCITable pci_table; ///< PCI 테이블
};


/**
 * @brief User 관련 정보
 */
struct Dot3UserInfo
{
  pthread_mutex_t mtx; ///< User 관련정보 동기화를 위한 뮤텍스
  bool user_mode; ///< User 모드 동작 여부 (USR이 등록되면 참이 된다)
  struct Dot3USRTable usr_table; ///< USR 테이블
  struct Dot3UASTable uas_table; ///< UAS 테이블
};


/**
 * @brief Management Information Base (MIB)
 */
struct Dot3MIB
{
  Dot3WSMSize wsm_max_len; ///< 처리 가능한 WSM 최대 길이
  struct Dot3WSRTable wsr_table; ///< WSR 테이블
  struct Dot3ProviderInfo provider_info; ///< Provider 관련 정보
  struct Dot3UserInfo user_info; ///< User 관련 정보
};


#endif //LIBDOT3_DOT3_MIB_H
