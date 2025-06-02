
## dot3-2016 라이브러리를 빌드하기 위한 CMakeLists.txt 파일


#
# 라이브러리 빌드 출력 설정
#
set(TARGET_LIB dot3-2016)
set(TARGET_LIB_FILE "lib${TARGET_LIB}.so")
set(TARGET_UNIT_TEST run-lib${TARGET_LIB}-unit-test)


#
# 안내 메시지 출력
#
message("[${TARGET_PLATFORM}][lib${TARGET_LIB}] BUILD")



#
# 단위테스트 빌드 시 적용되는 설정
#
if (BUILD_UNIT_TEST)
  set(CMAKE_C_OUTPUT_EXTENSION_REPLACE ON)
  set(CMAKE_CXX_OUTPUT_EXTENSION_REPLACE ON)
  add_compile_options(-g -O0 -fprofile-arcs -ftest-coverage)
  add_compile_definitions(_EXPORT_INTERNAL_FUNC_)
  link_libraries(gcov)
endif ()


#
# 라이브러리 빌드
#
add_library(${TARGET_LIB} SHARED)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/common)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/product/include)
target_include_directories(${TARGET_LIB} PRIVATE src)
target_link_libraries(${TARGET_LIB} PRIVATE rt)
target_sources(${TARGET_LIB} PRIVATE
               src/dot3.c
               src/dot3-log.c
               src/dot3-mib.h
               src/dot3-mpdu.c
               src/dot3-pci.c
               src/dot3-psr.c
               src/dot3-uas.c
               src/dot3-uas-mgmt.c
               src/dot3-usr.c
               src/dot3-wsa.c
               src/dot3-wsm.c
               src/dot3-wsr.c
               src/api/dot3-api.c
               src/api/dot3-api-pci.c
               src/api/dot3-api-psr.c
               src/api/dot3-api-uas.c
               src/api/dot3-api-usr.c
               src/api/dot3-api-wsa.c
               src/api/dot3-api-wsm.c
               src/api/dot3-api-wsr.c)
# asn.1 관련
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include/base)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include/dot3-2016)
target_include_directories(${TARGET_LIB} PRIVATE src/asn1/${ASN1_LIB_VENDOR})
target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/lib/${TARGET_BUILD})
if (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
  target_compile_definitions(${TARGET_LIB} PRIVATE _OBJASN1C_)
  target_link_libraries(${TARGET_LIB} PRIVATE objasn1-dot3-2016 asn1per asn1oer asn1rt)
  target_sources(${TARGET_LIB} PRIVATE
                 src/asn1/objasn1c/dot3-objasn1c.c
                 src/asn1/objasn1c/dot3-objasn1c-wsa-decode.c
                 src/asn1/objasn1c/dot3-objasn1c-wsa-encode.c
                 src/asn1/objasn1c/dot3-objasn1c-wsm-decode.c
                 src/asn1/objasn1c/dot3-objasn1c-wsm-encode.c)
elseif (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
  target_compile_definitions(${TARGET_LIB} PRIVATE _FFASN1C_)
  target_link_libraries(${TARGET_LIB} PRIVATE ffasn1-dot3-2016 ffasn1-base)
  target_sources(${TARGET_LIB} PRIVATE
                 src/asn1/ffasn1c/dot3-ffasn1c.c
                 src/asn1/ffasn1c/dot3-ffasn1c.h
                 src/asn1/ffasn1c/dot3-ffasn1c-wsa-decode.c
                 src/asn1/ffasn1c/dot3-ffasn1c-wsa-encode.c
                 src/asn1/ffasn1c/dot3-ffasn1c-wsm-decode.c
                 src/asn1/ffasn1c/dot3-ffasn1c-wsm-encode.c)
else ()
  message(FATAL_ERROR "Not supported asn.1 library for libdot3 - ${ASN1_LIB_VENDOR}")
endif ()


#
# 라이브러리 빌드 결과물 생성 경로 설정
#
if (NOT BUILD_UNIT_TEST)
  set(OUTPUT_DIR ${PROJECT_ROOT}/src/libs/product/bin/${TARGET_BUILD})
else ()
  set(OUTPUT_DIR ${PROJECT_ROOT}/src/libs/product/bin/${TARGET_BUILD}-debug)
endif ()
set_target_properties(${TARGET_LIB} PROPERTIES
                      ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIR}
                      LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR})


if (NOT BUILD_UNIT_TEST)
  #
  # 버전명이 추가된 라이브러리 파일 생성
  #
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          copy ${OUTPUT_DIR}/${TARGET_LIB_FILE} ${OUTPUT_DIR}/${TARGET_LIB_FILE}.${VERSION})

  #
  # 라이브러리 빌드 결과물(so 파일)을 어플리케이션 depend 디렉토리에 복사 (어플리케이션에서 링크할 수 있도록)
  #
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     make_directory ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     remove ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD}/${TARGET_LIB_FILE}*)
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy ${OUTPUT_DIR}/${TARGET_LIB_FILE} ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy ${OUTPUT_DIR}/${TARGET_LIB_FILE} ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD}/${TARGET_LIB_FILE}.${VERSION})

  #
  # 라이브러리 헤더 파일(h 파일)을 어플리케이션 depend 디렉토리에 복사 (어플리케이션에서 인클루드할 수 있도록)
  #
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     remove_directory ${PROJECT_ROOT}/src/apps/depend/include/${TARGET_LIB})
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy_directory ${PROJECT_ROOT}/src/libs/product/include/${TARGET_LIB} ${PROJECT_ROOT}/src/apps/depend/include/${TARGET_LIB})

  #
  # 의존 라이브러리 파일을 어플리케이션 depend 디렉토리로 복사 (어플리케이션에서 링크할 수 있도록)
  #
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/lib/${TARGET_BUILD}/*
                     ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
endif ()


#
# 단위테스트 빌드
#
if (BUILD_UNIT_TEST)
  add_executable(${TARGET_UNIT_TEST})
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/product/include)
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${GTEST_INCLUDE_DIR})
  target_link_directories(${TARGET_UNIT_TEST} PRIVATE ${OUTPUT_DIR})
  target_link_libraries(${TARGET_UNIT_TEST} PRIVATE ${TARGET_LIB} gtest gtest_main pthread)
  target_compile_options(${TARGET_UNIT_TEST} PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable)
  target_sources(${TARGET_UNIT_TEST} PRIVATE
                 test/unit-test/api/test-api-Dot3_AddPSR.cc
                 test/unit-test/api/test-api-Dot3_AddUSR.cc
                 test/unit-test/api/test-api-Dot3_AddWSR.cc
                 test/unit-test/api/test-api-Dot3_ChangePSR.cc
                 test/unit-test/api/test-api-Dot3_CheckWSRWithPSID.cc
                 test/unit-test/api/test-api-Dot3_ConstructWSA.cc
                 test/unit-test/api/test-api-Dot3_ConstructWSM.cc
                 test/unit-test/api/test-api-Dot3_ConstructWSMMPDU.cc
                 test/unit-test/api/test-api-Dot3_DeleteAllPSRs.cc
                 test/unit-test/api/test-api-Dot3_DeleteAllUSRs.cc
                 test/unit-test/api/test-api-Dot3_DeleteAllWSRs.cc
                 test/unit-test/api/test-api-Dot3_DeletePSR.cc
                 test/unit-test/api/test-api-Dot3_DeleteUSR.cc
                 test/unit-test/api/test-api-Dot3_DeleteWSR.cc
                 test/unit-test/api/test-api-Dot3_GetAllUASs.cc
                 test/unit-test/api/test-api-Dot3_GetPCIWithChannelNumber.cc
                 test/unit-test/api/test-api-Dot3_GetPSRWithPSID.cc
                 test/unit-test/api/test-api-Dot3_GetResultStr.cc
                 test/unit-test/api/test-api-Dot3_GetUASsWithMaxRCPI.cc
                 test/unit-test/api/test-api-Dot3_GetUASsWithPSID.cc
                 test/unit-test/api/test-api-Dot3_GetUASsWithPSIDAndSourceMACAddress.cc
                 test/unit-test/api/test-api-Dot3_GetUASsWithSourceMACAddress.cc
                 test/unit-test/api/test-api-Dot3_GetUSRWithPSID.cc
                 test/unit-test/api/test-api-Dot3_ParseWSA.cc
                 test/unit-test/api/test-api-Dot3_ParseWSM.cc
                 test/unit-test/api/test-api-Dot3_ParseWSMMPDU.cc
                 test/unit-test/api/test-api-Dot3_ProcessWSA.cc
                 test/unit-test/api/test-api-Dot3_SetPCI.cc
                 test/unit-test/api/test-api-Dot3_SetWSMMaxLength.cc
                 test/unit-test/api/test-api-Dot3_StartUASManagement.cc
                 test/unit-test/scenarios/test-construct-various-wsa.cc
                 test/unit-test/scenarios/test-parse-various-wsm-abnormal.cc
                 test/unit-test/scenarios/test-process-various-wsa.cc
                 test/unit-test/scenarios/test-process-various-wsa-abnormal.cc
                 test/unit-test/scenarios/test-uas-mgmt.cc
                 test/unit-test/test-libdot3.cc
                 test/unit-test/test-sample-data.cc
                 test/unit-test/test-sample-wsa.cc)

  # 단위테스트 실행 및 레포트 생성
  set(GTEST_REPORT_DIR ${PROJECT_ROOT}/docs/unit-test/gtest_report)
  set(UNIT_TEST_REPORT_DIR ${PROJECT_ROOT}/docs/unit-test/report/${TARGET_LIB})
  set(RESULT_REPORT_DIR ${UNIT_TEST_REPORT_DIR}/result)
  set(COVERAGE_REPORT_DIR ${UNIT_TEST_REPORT_DIR}/coverage)
  set(GCOV_FILE_DIR CMakeFiles/${TARGET_LIB}.dir/src)
  add_custom_target(${TARGET_LIB}test
                    COMMENT "Execute all unit test cases and generate result & coverage report"
                    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
                    DEPENDS ${TARGET_UNIT_TEST}
                    COMMAND mkdir -p ${RESULT_REPORT_DIR}
                    COMMAND mkdir -p ${COVERAGE_REPORT_DIR}
                    COMMAND rm -rf ${RESULT_REPORT_DIR}/*
                    COMMAND rm -rf ${COVERAGE_REPORT_DIR}/*
                    COMMAND ${CMAKE_CURRENT_LIST_DIR}/${TARGET_UNIT_TEST}
                            --gtest_output=xml:${GTEST_REPORT_DIR}/in/result.xml
                    COMMAND lcov -c -d ${GCOV_FILE_DIR} -o ${COVERAGE_REPORT_DIR}/${TARGET_LIB}.cov
                    COMMAND genhtml ${COVERAGE_REPORT_DIR}/${TARGET_LIB}.cov -o ${COVERAGE_REPORT_DIR}
                    COMMAND cd ${GTEST_REPORT_DIR} && dos2unix generate.sh && dos2unix scripts/*.py && chmod 777 generate.sh scripts/*.py && ./generate.sh
                    COMMAND rm ${GTEST_REPORT_DIR}/in/*
                    COMMAND mv ${GTEST_REPORT_DIR}/out/* ${RESULT_REPORT_DIR})
endif ()
