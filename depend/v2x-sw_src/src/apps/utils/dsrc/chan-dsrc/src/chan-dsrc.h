/**
 * @file
 * @brief chan-dsrc 유틸리티 메인 헤더 파일
 * @date 2019-08-15
 * @author gyun
 */

#ifndef V2X_CHAN_DSRC_H
#define V2X_CHAN_DSRC_H


// 시스템 헤더 파일
#include <stdbool.h>
#include <stdint.h>


/*
 * 입력 파라미터 기본값 - 해당되는 파라미터가 입력되지 않을 때 설정되는 기본값
 */
#define DEFAULT_IF_IDX 0 ///< 인터페이스 식별번호 기본값
#define DEFAULT_CHAN_NUM 172 ///< 접속채널 기본값


/**
 * @brief 어플리케이션 동작 유형
 */
enum eOperationType
{
  kOperationType_check, ///< 접속 중인 채널 확인
  kOperationType_config, ///< 채널접속 설정
  kOperationType_max = kOperationType_config
};
typedef unsigned int Operation; ///< @ref eOperationType


/*
 * 프로그램 내에서 사용되는 전역 변수 및 함수
 */
extern Operation g_op;
extern uint8_t g_if_num;
extern uint8_t g_if_idx;
extern WalChannelNumber g_chan_num[];

int CHAN_DSRC_ParsingInputParameters(int argc, char *argv[]);
int CHAN_DSRC_OpenAccessLibrary(WalLogLevel log_level);
int CHAN_DSRC_AccessChannel(uint8_t if_idx, WalChannelNumber ts0_chan_num, WalChannelNumber ts1_chan_num);
int CHAN_DSRC_PrintCurrentChannel(void);

#endif //V2X_CHAN_DSRC_H
