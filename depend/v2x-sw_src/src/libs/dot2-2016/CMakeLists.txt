
## dot2 라이브러리를 빌드하기 위한 CMakeLists.txt 파일


#
# 사용자 빌드 설정
#


#
# 라이브러리 빌드 출력 설정
#
set(TARGET_LIB dot2-2016)
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
  add_compile_definitions(_EXPORT_INTERNAL_FUNC_ _UNIT_TEST_)
  link_libraries(gcov)
  set(DOT2_SIGN_GEN openssl) # 단위테스트에는 Openssl만 사용 가능
  set(DOT2_SIGN_VERIFY openssl) # 단위테스트에는 Openssl만 사용 가능
endif ()


#
# 라이브러리 빌드
#
add_library(${TARGET_LIB} SHARED)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/common)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/openssl/${TARGET_OPENSSL_VER}/include)
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/product/include)
target_include_directories(${TARGET_LIB} PRIVATE src)
target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/openssl/${TARGET_OPENSSL_VER}/lib/${TARGET_BUILD})
target_link_libraries(${TARGET_LIB} PRIVATE crypto m pthread rt)
target_sources(${TARGET_LIB} PRIVATE
               src/api/dot2-api.c
               src/api/dot2-api-cert.c
               src/api/dot2-api-cmhf.c
               src/api/dot2-api-sec-profile.c
               src/api/dot2-api-spdu.c
               src/certificate/cert-info/dot2-ee-cert-cache.c
               src/certificate/cert-info/dot2-scc-cert-info.c
               src/certificate/cmh/dot2-cmh.c
               src/certificate/cmh/dot2-cmh-rotate.c
               src/certificate/cmh/dot2-cmh-sequential.c
               src/certificate/cmhf/dot2-cmhf-load.c
               src/certificate/cmhf/dot2-cmhf-load-rotate.c
               src/certificate/cmhf/dot2-cmhf-load-sequential.c
               src/certificate/cmhf/dot2-cmhf-make.c
               src/certificate/cmhf/dot2-cmhf-make-rotate.c
               src/certificate/cmhf/dot2-cmhf-make-sequential.c
               src/encrypt/dot2-ecies.c
               src/encrypt/dot2-encrypt.c
               src/sec-executer/openssl/dot2-openssl.c
               src/sec-executer/openssl/dot2-openssl-key.c
               src/sec-executer/openssl/dot2-openssl-key-generate.c
               src/sec-executer/openssl/dot2-openssl-linkage-value.c
               src/sec-executer/openssl/dot2-openssl-reconstruct-priv-key.c
               src/sec-executer/openssl/dot2-openssl-reconstruct-pub-key.c
               src/sec-executer/openssl/dot2-openssl-reconstruct-sign-butterfly-key.c
               src/sec-executer/openssl/dot2-openssl-sign-generate.c
               src/sec-executer/openssl/dot2-openssl-sign-precompute.c
               src/sec-executer/openssl/dot2-openssl-sign-verify.c
               src/sec-executer/dot2-sec-executer.c
               src/sec-profile/dot2-sec-profile.c
               src/sec-profile/dot2-sec-profile-replay.c
               src/signature/dot2-sign-verify.c
               src/spdu/dot2-spdu-consistency.c
               src/spdu/dot2-spdu-construct.c
               src/spdu/dot2-spdu-process.c
               src/spdu/dot2-spdu-process-work.c
               src/spdu/dot2-spdu-relevance.c
               src/dot2.c
               src/dot2-file.c
               src/dot2-log.c
               src/dot2-random.c)
if (${TARGET_PLATFORM} STREQUAL "craton2")
  target_sources(${TARGET_LIB} PRIVATE
                 ${PROJECT_ROOT}/src/libs/depend/dev/craton2/ref_src/link_layer/link_layer_interface.c
                 ${PROJECT_ROOT}/src/libs/depend/dev/craton2/ref_src/link_layer/linux_u/ipc/link_layer_ipc.c
                 ${PROJECT_ROOT}/src/libs/depend/dev/craton2/ref_src/link_layer/linux_u/local/link_layer_local.c
                 ${PROJECT_ROOT}/src/libs/depend/dev/craton2/ref_src/target_type/target_type_local.c)
endif ()

# asn.1 관련
target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include)
target_include_directories(${TARGET_LIB} PRIVATE src/asn1/${ASN1_LIB_VENDOR})
target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/lib/${TARGET_BUILD})
if (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
  target_compile_definitions(${TARGET_LIB} PRIVATE _OBJASN1C_)
  target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include/base)
  target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include/dot2-2021)
  target_link_libraries(${TARGET_LIB} PRIVATE objasn1-dot2-2021 asn1per asn1oer asn1rt)
  target_sources(${TARGET_LIB} PRIVATE
                 src/asn1/objasn1c/dot2-objasn1c-encode-spdu.c
                 src/asn1/objasn1c/dot2-objasn1c-parse.c
                 src/asn1/objasn1c/dot2-objasn1c-parse-cert.c
                 src/asn1/objasn1c/dot2-objasn1c-parse-ee-cert.c
                 src/asn1/objasn1c/dot2-objasn1c-parse-scc-cert.c
                 src/asn1/objasn1c/dot2-objasn1c-parse-spdu.c
                 src/asn1/objasn1c/dot2-objasn1c-process-spdu.c)
elseif (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
  target_compile_definitions(${TARGET_LIB} PRIVATE _FFASN1C_)
  target_link_libraries(${TARGET_LIB} PRIVATE ffasn1-dot2-2021 ffasn1-base)
  target_sources(${TARGET_LIB} PRIVATE
                 src/asn1/ffasn1c/dot2-ffasn1c-encode-spdu.c
                 src/asn1/ffasn1c/dot2-ffasn1c-parse.c
                 src/asn1/ffasn1c/dot2-ffasn1c-parse-cert.c
                 src/asn1/ffasn1c/dot2-ffasn1c-parse-ee-cert.c
                 src/asn1/ffasn1c/dot2-ffasn1c-parse-scc-cert.c
                 src/asn1/ffasn1c/dot2-ffasn1c-parse-spdu.c
                 src/asn1/ffasn1c/dot2-ffasn1c-process-spdu.c)
else ()
  message(FATAL_ERROR "Not supported asn.1 library for libdot2 - ${ASN1_LIB_VENDOR}")
endif ()

# 서명 검증 보안 연산 실행자 관련 라이브러리, 인클루드 헤더 정의
if (${DOT2_SIGN_VERIFY} STREQUAL "saf5400")
  target_compile_definitions(${TARGET_LIB} PRIVATE _SIGN_VERIFY_SAF5400_)
  target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/dev/saf5400/${TARGET_DEV_DSRC_SDK_VER}/include)
  target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/dev/saf5400/${TARGET_DEV_DSRC_SDK_VER}/lib/${TARGET_PLATFORM})
  target_link_libraries(${TARGET_LIB} PRIVATE LLC)
  target_sources(${TARGET_LIB} PRIVATE src/sec-executer/saf5400/dot2-saf5400.c)
  if (${TARGET_DEV_DSRC_SDK_VER} STREQUAL "0.10")
    target_compile_definitions(${TARGET_LIB} PRIVATE  _DSRC_CHIP_DEV_SAF5400_SDK_VER_0_10_)
  elseif (${TARGET_DEV_DSRC_SDK_VER} STREQUAL "0.15")
    target_compile_definitions(${TARGET_LIB} PRIVATE  _DSRC_CHIP_DEV_SAF5400_SDK_VER_0_15_)
  endif ()
  target_compile_options(${TARGET_LIB} PRIVATE -D_SEC_EXECUTER_DEV_NUM_=${TARGET_PLATFORM_DSRC_CHIP_DEV_NUM})
elseif (${DOT2_SIGN_VERIFY} STREQUAL "craton2")
  target_compile_definitions(${TARGET_LIB} PRIVATE _SIGN_VERIFY_CRATON2_)
  target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/dev/craton2/ref_src/include)
  target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/dev/craton2/include)
  target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/dev/craton2/lib/craton2)
  target_link_libraries(${TARGET_LIB} PRIVATE atlklocal_linux_u tomcrypt tommath m rt)
  target_sources(${TARGET_LIB} PRIVATE src/sec-executer/craton2/dot2-craton2.c)
elseif (${DOT2_SIGN_VERIFY} STREQUAL "openssl")
  target_compile_definitions(${TARGET_LIB} PRIVATE _SIGN_VERIFY_OPENSSL_)
else ()
  message(FATAL_ERROR "Not supported signature verification mechanism - ${DOT2_SIGN_VERIFY}")
endif ()

# SCMS 지원
if (SUPPORT_SCMS)
  target_compile_definitions(${TARGET_LIB} PRIVATE _SUPPORT_SCMS_)
  target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/curl/include)
  target_include_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/zip/include)
  target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/curl/lib/${TARGET_PLATFORM})
  target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/z/lib/${TARGET_PLATFORM})
  target_link_directories(${TARGET_LIB} PRIVATE ${PROJECT_ROOT}/src/libs/depend/zip/lib/${TARGET_PLATFORM})
  target_link_libraries(${TARGET_LIB} PRIVATE curl ssl zip)
  target_sources(${TARGET_LIB} PRIVATE
                 src/api/dot2-api-lcm.c
                 src/lcm/dot2-lcm.c
                 src/lcm/dot2-lcm-crl.c
                 src/lcm/dot2-lcm-crl-hash.c
                 src/lcm/dot2-lcm-crl-lv.c
                 src/lcm/dot2-lcm-download.c
                 src/lcm/dot2-lcm-download-app-cert.c
                 src/lcm/dot2-lcm-download-id-cert.c
                 src/lcm/dot2-lcm-download-pseudonym-cert.c
                 src/lcm/dot2-lcm-ecrequest.c
                 src/lcm/dot2-lcm-ecresponse.c
                 src/lcm/dot2-lcm-https.c
                 src/lcm/dot2-lcm-https-get.c
                 src/lcm/dot2-lcm-https-post.c
                 src/lcm/dot2-lcm-lccf.c
                 src/lcm/dot2-lcm-lpf.c
                 src/lcm/dot2-lcm-provisioning.c
                 src/lcm/dot2-lcm-provisioning-app-cert.c
                 src/lcm/dot2-lcm-provisioning-id-cert.c
                 src/lcm/dot2-lcm-provisioning-pseudonym-cert.c)
  if (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
    target_link_libraries(${TARGET_LIB} PRIVATE objasn1-dot2-2021)
    target_sources(${TARGET_LIB} PRIVATE
                   src/asn1/objasn1c/dot2-objasn1c-lcm.c
                   src/asn1/objasn1c/dot2-objasn1c-lcm-crl.c
                   src/asn1/objasn1c/dot2-objasn1c-lcm-download.c
                   src/asn1/objasn1c/dot2-objasn1c-lcm-ecrequest.c
                   src/asn1/objasn1c/dot2-objasn1c-lcm-ecresponse.c
                   src/asn1/objasn1c/dot2-objasn1c-lcm-lccf.c
                   src/asn1/objasn1c/dot2-objasn1c-lcm-provisioning.c
                   src/asn1/objasn1c/dot2-objasn1c-lcm-provisioning-app-cert.c
                   src/asn1/objasn1c/dot2-objasn1c-lcm-provisioning-id-cert.c
                   src/asn1/objasn1c/dot2-objasn1c-lcm-provisioning-pseudonym-cert.c)
  elseif (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
    target_link_libraries(${TARGET_LIB} PRIVATE ffasn1-dot2-2021)
    target_sources(${TARGET_LIB} PRIVATE
                   src/asn1/ffasn1c/lcm/dot2-ffasn1c-lcm.c
                   src/asn1/ffasn1c/lcm/dot2-ffasn1c-lcm-crl.c
                   src/asn1/ffasn1c/lcm/dot2-ffasn1c-lcm-download.c
                   src/asn1/ffasn1c/lcm/dot2-ffasn1c-lcm-ecrequest.c
                   src/asn1/ffasn1c/lcm/dot2-ffasn1c-lcm-ecresponse.c
                   src/asn1/ffasn1c/lcm/dot2-ffasn1c-lcm-lccf.c
                   src/asn1/ffasn1c/lcm/dot2-ffasn1c-lcm-provisioning.c
                   src/asn1/ffasn1c/lcm/dot2-ffasn1c-lcm-provisioning-app-cert.c
                   src/asn1/ffasn1c/lcm/dot2-ffasn1c-lcm-provisioning-id-cert.c
                   src/asn1/ffasn1c/lcm/dot2-ffasn1c-lcm-provisioning-pseudonym-cert.c)
  else ()
    message(FATAL_ERROR "Not supported asn.1 library for libdot2 - ${ASN1_LIB_VENDOR}")
  endif ()
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
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy ${PROJECT_ROOT}/src/libs/depend/openssl/${TARGET_OPENSSL_VER}/lib/${TARGET_BUILD}/*
                     ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy ${PROJECT_ROOT}/src/libs/depend/curl/lib/${TARGET_BUILD}/*
                     ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
  add_custom_command(TARGET ${TARGET_LIB} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                     copy ${PROJECT_ROOT}/src/libs/depend/zip/lib/${TARGET_BUILD}/*
                     ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
endif ()


#
# 단위테스트 빌드
#
if (BUILD_UNIT_TEST)
  add_executable(${TARGET_UNIT_TEST})
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/product/include)
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/common)
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE src)
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${GTEST_INCLUDE_DIR})
  target_link_directories(${TARGET_UNIT_TEST} PRIVATE ${OUTPUT_DIR})
  target_link_libraries(${TARGET_UNIT_TEST} PRIVATE ${TARGET_LIB} crypto gtest gtest_main pthread)
  target_compile_options(${TARGET_UNIT_TEST} PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable)
  target_compile_definitions(${TARGET_UNIT_TEST} PRIVATE _SIGN_VERIFY_OPENSSL_)
  target_sources(${TARGET_UNIT_TEST} PRIVATE
                 test/unit-test/api/test-api-Dot2_AddSCCCert.cc
                 test/unit-test/api/test-api-Dot2_AddSecProfile.cc
                 test/unit-test/api/test-api-Dot2_ConstructSPDU-SignedData.cc
                 test/unit-test/api/test-api-Dot2_ConstructSPDU-UnsecuredData.cc
                 test/unit-test/api/test-api-Dot2_ConvertSystemTimeToTime32.cc
                 test/unit-test/api/test-api-Dot2_Init.cc
                 test/unit-test/api/test-api-Dot2_LoadCMHF.cc
                 test/unit-test/api/test-api-Dot2_LoadCMHFFile.cc
                 test/unit-test/api/test-api-Dot2_LoadSCCCertFile.cc
                 test/unit-test/api/test-api-Dot2_MakeApplicationCertCMHF.cc
                 test/unit-test/api/test-api-Dot2_MakeIdentificationCertCMHF.cc
                 test/unit-test/api/test-api-Dot2_MakePseudonymCertCMHF.cc
                 test/unit-test/api/test-api-Dot2_ProcessSPDU-SignedData.cc
                 test/unit-test/api/test-api-Dot2_ProcessSPDU-UnsecuredData.cc
                 test/unit-test/api/test-api-Dot2_RemoveExpiredCMH.cc
                 test/unit-test/api/test-api-Dot2_RemoveExpiredEECertCache.cc
                 test/unit-test/api/test-api-Dot2_RemoveExpiredSCCCert.cc
                 test/unit-test/internal/cert-info/test-add-scc-cert.cc
                 test/unit-test/internal/cmhf/test-load-rotate-cmhf.cc
                 test/unit-test/internal/cmhf/test-load-sequential-cmhf.cc
                 test/unit-test/internal/cmhf/test-make-rotate-cmhf.cc
                 test/unit-test/internal/cmhf/test-make-sequential-cmhf.cc
                 test/unit-test/internal/consistency-check/test-consistency-check-internal.cc
                 test/unit-test/internal/consistency-check/test-consistency-check-sample-data.cc
                 test/unit-test/internal/consistency-check/test-consistency-check-valid-expiry-time.cc
                 test/unit-test/internal/consistency-check/test-consistency-check-valid-gen-location.cc
                 test/unit-test/internal/consistency-check/test-consistency-check-valid-gen-time.cc
                 test/unit-test/internal/encrypt/test-aes-ccm.cc
                 test/unit-test/internal/encrypt/test-ecdh.cc
                 test/unit-test/internal/encrypt/test-ecies.cc
                 test/unit-test/internal/encrypt/test-encrypt-decrypt.cc
                 test/unit-test/internal/encrypt/test-encrypt-decrypt-data-and-key.cc
                 test/unit-test/internal/encrypt/test-hmac-sha256.cc
                 test/unit-test/internal/encrypt/test-kdf2-sha256.cc
                 test/unit-test/internal/key/test-reconstruct-enc-butterfly-key.cc
                 test/unit-test/internal/key/test-check-keypair.cc
                 test/unit-test/internal/key/test-reconstruct-priv-key.cc
                 test/unit-test/internal/key/test-reconstruct-key.cc
                 test/unit-test/internal/key/test-reconstruct-sign-butterfly-key.cc
                 test/unit-test/internal/key/test-y-recovery.cc
                 test/unit-test/internal/random/test-random.cc
                 test/unit-test/internal/relevance-check/test-relevance-check-cert-expiry.cc
                 test/unit-test/internal/relevance-check/test-relevance-check-expiry-time.cc
                 test/unit-test/internal/relevance-check/test-relevance-check-fresheness.cc
                 test/unit-test/internal/relevance-check/test-relevance-check-future-generation.cc
                 test/unit-test/internal/relevance-check/test-relevance-check-location.cc
                 test/unit-test/internal/relevance-check/test-relevance-check-replay.cc
                 test/unit-test/internal/relevance-check/test-relevance-check-sample-data.cc
                 test/unit-test/internal/sec-profile/test-sec-profile-find.cc
                 test/unit-test/internal/sec-profile/test-sec-profile-replay.cc
                 test/unit-test/internal/sec-profile/test-sec-profile-signerid.cc
                 test/unit-test/internal/signature/test-sign-generate.cc
                 test/unit-test/internal/signature/test-sign-verify.cc
                 test/unit-test/internal/signature/test-verify-cert-sign.cc
                 test/unit-test/scenarios/test-construct-signed-spdu.cc
                 test/unit-test/scenarios/test-construct-signed-spdu-header-info.cc
                 test/unit-test/scenarios/test-construct-signed-spdu-sign-type.cc
                 test/unit-test/scenarios/test-construct-signed-spdu-signer-id.cc
                 test/unit-test/scenarios/test-exchange-signed-spdu.cc
                 test/unit-test/scenarios/test-process-signed-spdu.cc
                 test/unit-test/scenarios/test-process-signed-spdu-consistency-check-internal.cc
                 test/unit-test/scenarios/test-process-signed-spdu-consistency-check-valid-expiry-time.cc
                 test/unit-test/scenarios/test-process-signed-spdu-consistency-check-valid-gen-location.cc
                 test/unit-test/scenarios/test-process-signed-spdu-consistency-check-valid-gen-time.cc
                 test/unit-test/scenarios/test-process-signed-spdu-relevance-check-cert-expiry.cc
                 test/unit-test/scenarios/test-process-signed-spdu-relevance-check-expiry-time.cc
                 test/unit-test/scenarios/test-process-signed-spdu-relevance-check-freshness.cc
                 test/unit-test/scenarios/test-process-signed-spdu-relevance-check-future-generation.cc
                 test/unit-test/scenarios/test-process-signed-spdu-relevance-check-location.cc
                 test/unit-test/scenarios/test-process-signed-spdu-relevance-check-replay.cc
                 test/unit-test/test-common-funcs/test-common-funcs.cc
                 test/unit-test/test-common-funcs/test-common-funcs-ca-cert.cc
                 test/unit-test/test-common-funcs/test-common-funcs-scc-cert.cc
                 test/unit-test/test-common-funcs/test-common-funcs-cmh.cc
                 test/unit-test/test-common-funcs/test-common-funcs-obu-cert.cc
                 test/unit-test/test-common-funcs/test-common-funcs-other-cert.cc
                 test/unit-test/test-common-funcs/test-common-funcs-rse-cert.cc
                 test/unit-test/test-common-funcs/test-common-funcs-sec-profile.cc
                 test/unit-test/test-common-funcs/test-common-funcs-spdu.cc
                 test/unit-test/test-vectors/test-vector-ca-cert.cc
                 test/unit-test/test-vectors/test-vector-obu-cert.cc
                 test/unit-test/test-vectors/test-vector-other-cert.cc
                 test/unit-test/test-vectors/test-vector-rse-cert.cc
                 test/unit-test/test-vectors/test-vector-cert-bundle-0.cc
                 test/unit-test/test-vectors/test-vector-cert-bundle-1.cc
                 test/unit-test/test-vectors/test-vector-cert-bundle-2.cc
                 test/unit-test/test-vectors/test-vector-cert-bundle-3.cc
                 test/unit-test/test-vectors/test-vector-cmhf.cc
                 test/unit-test/test-vectors/test-vector-enrollment-cert.cc
                 test/unit-test/test-vectors/test-vector-signature.cc
                 test/unit-test/test-vectors/test-vector-scc-cert.cc
                 test/unit-test/test-vectors/test-vector-sec-profile.cc
                 test/unit-test/test-vectors/test-vector-signed-data.cc
                 test/unit-test/test-vectors/test-vector-spdu-consistency-check.cc
                 test/unit-test/test-vectors/test-vector-unsecured-data.cc
                 test/unit-test/test-libdot2.cc)

  # asn.1 관련
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include)
  target_include_directories(${TARGET_UNIT_TEST} PRIVATE src/asn1/${ASN1_LIB_VENDOR})
  target_link_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/lib/${TARGET_BUILD})
  if (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
    target_compile_definitions(${TARGET_UNIT_TEST} PRIVATE _OBJASN1C_)
    target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include/base)
    target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/include/dot2-2016)
    target_link_libraries(${TARGET_UNIT_TEST} PRIVATE objasn1-dot2-2021)
  elseif (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
    target_compile_definitions(${TARGET_UNIT_TEST} PRIVATE _FFASN1C_)
    target_link_libraries(${TARGET_UNIT_TEST} PRIVATE ffasn1-dot2-2021 ffasn1-base)
  else ()
    message(FATAL_ERROR "Not supported asn.1 library for libdot2 - ${ASN1_LIB_VENDOR}")
  endif ()

  # 서명생성파라미터 사전계산 기능 지원 여부
  if (SUPPORT_PRECOMPUTE_SIGNINIG_PARAMS)
    target_compile_definitions(${TARGET_UNIT_TEST} PRIVATE _SUPPORT_PRECOMPUTE_SIGNINIG_PARAMS_)
  endif ()

  # SCMS 지원
  if (SUPPORT_SCMS)
    target_compile_definitions(${TARGET_UNIT_TEST} PRIVATE _SUPPORT_SCMS_)
    target_include_directories(${TARGET_UNIT_TEST} PRIVATE ${PROJECT_ROOT}/src/libs/depend/curl/include)
    target_sources(${TARGET_UNIT_TEST} PRIVATE
                   test/unit-test/api/test-api-Dot2_ConfigLCM.cc
                   test/unit-test/api/test-api-Dot2_ConstructECRequest.cc
                   test/unit-test/api/test-api-Dot2_DownloadAppCert.cc
                   test/unit-test/api/test-api-Dot2_DownloadCertDownloadInfo.cc
                   test/unit-test/api/test-api-Dot2_DownloadCRL.cc
                   test/unit-test/api/test-api-Dot2_DownloadIdCert.cc
                   test/unit-test/api/test-api-Dot2_DownloadLCCF.cc
                   test/unit-test/api/test-api-Dot2_DownloadLPF.cc
                   test/unit-test/api/test-api-Dot2_DownloadPseudonymCert.cc
                   test/unit-test/api/test-api-Dot2_LoadCRL.cc
                   test/unit-test/api/test-api-Dot2_LoadCRLFile.cc
                   test/unit-test/api/test-api-Dot2_ProcessECResponse.cc
                   test/unit-test/api/test-api-Dot2_RequestAppCertProvisioning.cc
                   test/unit-test/api/test-api-Dot2_RequestIdCertProvisioning.cc
                   test/unit-test/api/test-api-Dot2_RequestPseudonymCertProvisioning.cc
                   test/unit-test/internal/lcm/test-lcm-ecrequest.cc
                   test/unit-test/internal/lcm/test-lcm-lccf.cc
                   test/unit-test/test-vectors/test-vector-lcm-bluetech.cc
                   test/unit-test/test-vectors/test-vector-lcm-crosscert.cc
                   test/unit-test/test-vectors/test-vector-lcm-ecrequest.cc
                   test/unit-test/test-vectors/test-vector-lcm-ssotech.cc)
  endif ()

  if (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
    # 단위테스트 실행 파일 실행 시, libasn1per.so를 로딩할 수 있도록 /usr/lib/에 복사한다.
    # 왜 이 파일만 그래야하는지는 잘 모르겠다..
    add_custom_command(TARGET ${TARGET_UNIT_TEST} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                       copy ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/lib/${TARGET_BUILD}/libasn1per.so /usr/lib)
    add_custom_command(TARGET ${TARGET_UNIT_TEST} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
                       copy ${PROJECT_ROOT}/src/libs/depend/${ASN1_LIB_VENDOR}/${ASN1_LIB_VERSION}/lib/${TARGET_BUILD}/libasn1oer.so /usr/lib)
  endif ()

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
                    COMMAND rm -rf ${GTEST_REPORT_DIR}/in/*
                    COMMAND ${CMAKE_CURRENT_LIST_DIR}/${TARGET_UNIT_TEST}
                    --gtest_output=xml:${GTEST_REPORT_DIR}/in/result.xml
                    COMMAND lcov -c -d ${GCOV_FILE_DIR} -o ${COVERAGE_REPORT_DIR}/${TARGET_LIB}.cov
                    COMMAND genhtml ${COVERAGE_REPORT_DIR}/${TARGET_LIB}.cov -o ${COVERAGE_REPORT_DIR}
                    COMMAND cd ${GTEST_REPORT_DIR} && dos2unix generate.sh && dos2unix scripts/*.py && ./generate.sh
                    COMMAND rm ${GTEST_REPORT_DIR}/in/*
                    COMMAND mv ${GTEST_REPORT_DIR}/out/* ${RESULT_REPORT_DIR})
endif ()
