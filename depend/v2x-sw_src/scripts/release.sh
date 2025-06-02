#!/bin/bash

# v2x-sw 릴리즈 스크립트
#  - 본 스크립트는 x64용 도커 컨테이너에서 실행된다.
#  - 본 스크립트 실행 시 릴리즈 대상이 아닌 항목에 관련된 파일들이 모두 삭제된다.

# 릴리즈 대상 항목 선택 (y: 릴리즈, n: 삭제)
condor=n
craton2=n
secton=n
ag550q=n
#ffasn1c=y 일단 ffasn1c는 무조건 포함되는 것으로 한다.
objasn1c=n
objasn1c_760p=n # objasn1c=y인 경우에만 의미가 있음
objasn1c_744h=n # objasn1c=y인 경우에만 의미가 있음
objasn1c_764t=n # objasn1c=y인 경우에만 의미가 있음
libcvcoctci=n
libdot2=y
libdot2_scms=y # libdot2=y인 경우에만 의미가 있음
libdot3=y
libj29451=y
liblteaccess=n
libltev2x_hal=n
libwlanaccess=n
eu=n

## Delete files for condor5/condor5v/condor6
delete_condor()
{
  # 의존 라이브러리들 삭제
  rm -rf src/libs/depend/curl/lib/condor5
  rm -rf src/libs/depend/curl/lib/condor5v
  rm -rf src/libs/depend/curl/lib/condor6
  rm -rf src/libs/depend/dev/saf5400/0.10/lib/condor5
  rm -rf src/libs/depend/dev/saf5400/0.10/lib/condor5v
  rm -rf src/libs/depend/dev/saf5400/0.10/lib/condor6
  rm -rf src/libs/depend/dev/saf5400/0.13/lib/condor5
  rm -rf src/libs/depend/dev/saf5400/0.13/lib/condor5v
  rm -rf src/libs/depend/dev/saf5400/0.13/lib/condor6
  rm -rf src/libs/depend/dev/saf5400/0.15/lib/condor5
  rm -rf src/libs/depend/dev/saf5400/0.15/lib/condor5v
  rm -rf src/libs/depend/dev/saf5400/0.15/lib/condor6
  rm -rf src/libs/depend/dev/ag15/lib/condor5
  rm -rf src/libs/depend/dev/ag15/lib/condor5v
  rm -rf src/libs/depend/dev/ag15/lib/condor6
  rm -rf src/libs/depend/ffasn1c/lib/condor5
  rm -rf src/libs/depend/ffasn1c/lib/condor5v
  rm -rf src/libs/depend/ffasn1c/lib/condor6
  rm -rf src/libs/depend/gpsd/3.23.1/f9k/lib/condor5
  rm -rf src/libs/depend/gpsd/3.23.1/f9k/lib/condor5v
  rm -rf src/libs/depend/gpsd/3.23.1/f9k/lib/condor6
  rm -rf src/libs/depend/objasn1c/lib/condor5
  rm -rf src/libs/depend/objasn1c/lib/condor5v
  rm -rf src/libs/depend/objasn1c/lib/condor6
  rm -rf src/libs/depend/openssl/lib/condor5
  rm -rf src/libs/depend/openssl/lib/condor5v
  rm -rf src/libs/depend/openssl/lib/condor6
  rm -rf src/libs/depend/zip/lib/condor5
  rm -rf src/libs/depend/zip/lib/condor5v
  rm -rf src/libs/depend/zip/lib/condor6

  # 도커 컨테이너 삭제
  rm -rf dockers/condor5
  rm -rf dockers/condor5v
  rm -rf dockers/condor6

  # 라이브러리 파일(빌드 결과물) 삭제
  rm -rf src/libs/product/bin/condor5
  rm -rf src/libs/product/bin/condor5v
  rm -rf src/libs/product/bin/condor6
  rm -rf src/apps/depend/lib/condor5
  rm -rf src/apps/depend/lib/condor5v
  rm -rf src/apps/depend/lib/condor6

  # 어플리케이션 파일(빌드 결과물) 삭제
  rm -rf src/apps/output/condor5
  rm -rf src/apps/output/condor5v
  rm -rf src/apps/output/condor6

  # 라이브러리 소스코드 삭제
  rm -rf src/libs/dot2-2016/src/sec-executer/saf5400
  rm -rf src/libs/dot2-2021/src/sec-executer/saf5400
  if [ "$secton" == "n" ]; then
    rm -rf src/libs/wlanaccess/src/saf5xxx
  fi
  rm -rf src/libs/lteaccess/src/ag15
}


## Delete files for craton2
delete_craton2()
{
  # 의존 라이브러리들 삭제
  rm -rf src/libs/depend/dev/craton2
  rm -rf src/libs/depend/ffasn1c/lib/craton2
  rm -rf src/libs/depend/gpsd/3.14/orig/lib/craton2
  rm -rf src/libs/depend/openssl/lib/craton2

  # 도커 컨테이너 삭제
  rm -rf dockers/craton2

  # 라이브러리 파일(빌드 결과물) 삭제
  rm -rf src/libs/product/bin/craton2
  rm -rf src/apps/depend/lib/craton2

  # 어플리케이션 파일(빌드 결과물) 삭제
  rm -rf src/apps/output/craton2/

  # 라이브러리 소스코드 삭제
  rm -rf src/libs/dot2-2016/src/sec-executer/craton2
  rm -rf src/libs/dot2-2021/src/sec-executer/craton2
  rm -rf src/libs/wlanaccess/src/craton2

  # 스크립트 삭제
  rm -rf scripts/ip_test.craton2.sh
  rm -rf scripts/start_tcia.craton2.sh
}

## Delete files for ag550q
delete_ag550q()
{
  # 의존 라이브러리들 삭제
  rm -rf src/libs/depend/dev/AG550Q
  rm -rf src/libs/depend/curl/lib/ag550q
  rm -rf src/libs/depend/ffasn1c/lib/ag550q
  rm -rf src/libs/depend/gpsd/3.23.1/f9k/lib/ag550q
  rm -rf src/libs/depend/openssl/3.0.12/lib/ag550q
  rm -rf src/libs/depend/zip/lib/ag550q

  # 도커 컨테이너 삭제
  rm -rf dockers/ag550q

  # 라이브러리 파일(빌드 결과물) 삭제
  rm -rf src/libs/product/bin/ag550q
  rm -rf src/apps/depend/lib/ag550q

  # 어플리케이션 파일(빌드 결과물) 삭제
  rm -rf src/apps/output/ag550q/

  # 라이브러리 소스코드 삭제
  rm -rf src/libs/dot2-2016/src/sec-executer/ag550q
  rm -rf src/libs/dot2-2021/src/sec-executer/ag550q
  rm -rf src/libs/ltev2x-hal/src/dev/AG55xQ

  # 스크립트 삭제
  rm -rf scripts/ip_test.craton2.sh
  rm -rf scripts/start_tcia.craton2.sh
}


## Delete files for secton
delete_secton()
{
  # 의존 라이브러리들 삭제
  rm -rf src/libs/depend/dev/saf5400/0.10/lib/kvh1a
  rm -rf src/libs/depend/dev/saf5400/0.13/lib/kvh1a
  rm -rf src/libs/depend/dev/saf5400/0.15/lib/kvh1a
  rm -rf src/libs/depend/dev/SECTON
  rm -rf src/libs/depend/curl/lib/kvh1a
  rm -rf src/libs/depend/ffasn1c/lib/kvh1a
  rm -rf src/libs/depend/gpsd/3.23.1/f9k/lib/kvh1a
  rm -rf src/libs/depend/openssl/3.0.12/lib/kvh1a
  rm -rf src/libs/depend/zip/lib/kvh1a

  # 도커 컨테이너 삭제
  rm -rf dockers/kvh1a

  # 라이브러리 파일(빌드 결과물) 삭제
  rm -rf src/libs/product/bin/kvh1a
  rm -rf src/apps/depend/lib/kvh1a

  # 어플리케이션 파일(빌드 결과물) 삭제
  rm -rf src/apps/output/kvh1a/

  # 라이브러리 소스코드 삭제
  rm -rf src/libs/dot2-2016/src/sec-executer/kvh1a
  rm -rf src/libs/dot2-2021/src/sec-executer/kvh1a
  if [ "$condor" == "n" ]; then
    rm -rf src/libs/wlanaccess/src/saf5xxx
  fi

  # 스크립트 삭제
  rm -rf scripts/ip_test.craton2.sh
  rm -rf scripts/start_tcia.craton2.sh
}


## Delete files for cmake in current directory
delete_cmake_stuff()
{
  rm -rf $1/cmake-build-debug
  rm -rf $1/CMakeFiles
  rm -rf $1/cmake_install.cmake
  rm -rf $1/CMakeCache.txt
  rm -rf $1/Makefile
}


## Delete all files for cmake in project
delete_cmake()
{
  delete_cmake_stuff .

  delete_cmake_stuff src/apps/utils/common/tcia-2023
  delete_cmake_stuff src/apps/utils/common/app-cert-req
  delete_cmake_stuff src/apps/utils/common/bootstrap
  delete_cmake_stuff src/apps/utils/common/bsmd
  delete_cmake_stuff src/apps/utils/common/cmhf
  delete_cmake_stuff src/apps/utils/common/crl-req
  delete_cmake_stuff src/apps/utils/common/id-cert-req
  delete_cmake_stuff src/apps/utils/common/pseudonym-cert-req
  delete_cmake_stuff src/apps/utils/common/sec-tester
  delete_cmake_stuff src/apps/utils/common/secton-aes

  delete_cmake_stuff src/apps/utils/dsrc/addr-dsrc
  delete_cmake_stuff src/apps/utils/dsrc/chan-dsrc
  delete_cmake_stuff src/apps/utils/dsrc/init-dsrc
  delete_cmake_stuff src/apps/utils/dsrc/sdee-dsrc
  delete_cmake_stuff src/apps/utils/dsrc/wsm-dsrc

  delete_cmake_stuff src/apps/utils/ltev2x/ip-ltev2x
  delete_cmake_stuff src/apps/utils/ltev2x/sdee-ltev2x
  delete_cmake_stuff src/apps/utils/ltev2x/wsm-ltev2x
  delete_cmake_stuff src/apps/utils/ltev2x/wsm-test-ltev2x

  delete_cmake_stuff src/libs/cvcoctci
  delete_cmake_stuff src/libs/cvcoctci3
  delete_cmake_stuff src/libs/cvcoctci-2023
  delete_cmake_stuff src/libs/dot2
  delete_cmake_stuff src/libs/dot2-2016
  delete_cmake_stuff src/libs/dot2-2021
  delete_cmake_stuff src/libs/dot3
  delete_cmake_stuff src/libs/dot3-2016
  delete_cmake_stuff src/libs/dot3-2020
  delete_cmake_stuff src/libs/geonet
  delete_cmake_stuff src/libs/gn6
  delete_cmake_stuff src/libs/j29451
  delete_cmake_stuff src/libs/j29451/libpathgen
  delete_cmake_stuff src/libs/lteaccess
  delete_cmake_stuff src/libs/wlanaccess
  delete_cmake_stuff src/libs/ltev2x-hal
}


## Delete all files for codesonar in projct
delete_codesonar()
{
  rm -rf dockers/codesonar
  rm -rf *.prj_files
  rm -rf *.conf
  rm -rf *.prj
  rm -rf do-rte-test.sh
}


## Delete EU stack software
delete_eu()
{
  rm -rf src/libs/geonet
  rm -rf src/libs/gn6
  rm -rf src/libs/product/include/geonet
  rm -rf src/libs/product/include/gn6asl
}


# 760p 버전 objasn1c 관련 파일 삭제
delete_objasn1c_760p()
{
  rm -rf src/libs/depend/objasn1c/760p
}


# 744h 버전 objasn1c 관련 파일 삭제
delete_objasn1c_744h()
{
  rm -rf src/libs/depend/objasn1c/744h
}


# 764t 버전 objasn1c 관련 파일 삭제
delete_objasn1c_764t()
{
  rm -rf src/libs/depend/objasn1c/764t
}


## Delete objasn1c related code
delete_objasn1c()
{
  # 의존 라이브러리 파일 삭제
  rm -rf src/libs/depend/objasn1c

  # 각 라이브러리의 objasn1c 관련 코드 삭제
  rm -rf src/libs/cvcoctci/src/asn1/objasn1c
  rm -rf src/libs/cvcoctci3/src/asn1/objasn1c
  rm -rf src/libs/cvcoctci-2023/src/asn1/objasn1c
  rm -rf src/libs/dot2/src/asn1/objasn1c
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c
  rm -rf src/libs/dot2-2021/src/asn1/objasn1c
  rm -rf src/libs/dot3/src/asn1/objasn1c
  rm -rf src/libs/dot3-2016/src/asn1/objasn1c
  rm -rf src/libs/dot3-2020/src/asn1/objasn1c
  rm -rf src/libs/j29451/src/asn1/objasn1c

  # 라이브러리 결과 디렉토리 내 의존 라이브러리 파일 삭제
  rm -rf src/libs/product/bin/condor5/libasn1*
  rm -rf src/libs/product/bin/condor5/libobjasn1*
  rm -rf src/libs/product/bin/condor5v/libasn1*
  rm -rf src/libs/product/bin/condor5v/libobjasn1*
  rm -rf src/libs/product/bin/condor6/libasn1*
  rm -rf src/libs/product/bin/condor6/libobjasn1*
  rm -rf src/libs/product/bin/craton2/libasn1*
  rm -rf src/libs/product/bin/craton2/libobjasn1*
  rm -rf src/libs/product/bin/kvh1a/libasn1*
  rm -rf src/libs/product/bin/kvh1a/libobjasn1*
  rm -rf src/libs/product/bin/x64/libasn1*
  rm -rf src/libs/product/bin/x64/libobjasn1*
  rm -rf src/libs/product/bin/x64-debug/libasn1*
  rm -rf src/libs/product/bin/x64-debug/libobjasn1*

  # 어플리케이션 의존 라이브러리 파일 삭제
  rm -rf src/apps/depend/lib/condor5/libasn1*
  rm -rf src/apps/depend/lib/condor5/libobjasn1*
  rm -rf src/apps/depend/lib/condor5v/libasn1*
  rm -rf src/apps/depend/lib/condor5v/libobjasn1*
  rm -rf src/apps/depend/lib/condor6/libasn1*
  rm -rf src/apps/depend/lib/condor6/libobjasn1*
  rm -rf src/apps/depend/lib/craton2/libasn1*
  rm -rf src/apps/depend/lib/craton2/libobjasn1*
  rm -rf src/apps/depend/lib/kvh1a/libasn1*
  rm -rf src/apps/depend/lib/kvh1a/libobjasn1*
  rm -rf src/apps/depend/lib/x64/libasn1*
  rm -rf src/apps/depend/lib/x64/libobjasn1*
  rm -rf src/apps/depend/lib/x64-debug/libasn1*
  rm -rf src/apps/depend/lib/x64-debug/libobjasn1*
}


## Delete common files
delete_common()
{
  rm -rf .git
  rm -rf .idea
  rm -rf .gitignore
  rm -rf do-unit-test.sh

  rm -rf docs/unit-test/report/dot2/*
  rm -rf docs/unit-test/report/dot3/*
  rm -rf docs/unit-test/report/j29451/*
  rm -rf docs/unit-test/report/lteaccess/*
  rm -rf docs/unit-test/report/wlanaccess/*

  delete_cmake

  delete_codesonar

  # 라이브러리 빌드 결과물 모두 삭제
  rm -rf src/libs/product/bin/condor5/*
  rm -rf src/libs/product/bin/condor5v/*
  rm -rf src/libs/product/bin/condor6/*
  rm -rf src/libs/product/bin/craton2/*
  rm -rf src/libs/product/bin/kvh1a/*
  rm -rf src/libs/product/bin/kvh1a-debug/*
  rm -rf src/libs/product/bin/x64/*
  rm -rf src/libs/product/bin/x64-debug/*
  rm -rf src/libs/product/bin/*

  # 어플리케이션 의존 라이브러리 빌드 결과파일 모두 삭제
  rm -rf src/apps/depend/lib/condor5/*
  rm -rf src/apps/depend/lib/condor5v/*
  rm -rf src/apps/depend/lib/condor6/*
  rm -rf src/apps/depend/lib/craton2/*
  rm -rf src/apps/depend/lib/kvh1a/*
  rm -rf src/apps/depend/lib/x64/*
  rm -rf src/apps/depend/lib/x64-debug/*
  rm -rf src/apps/depend/lib/hga/*

  # 어플리케이션 빌드 결과물 모두 삭제
  rm -rf src/apps/output/condor5/*
  rm -rf src/apps/output/condor5v/*
  rm -rf src/apps/output/condor6/*
  rm -rf src/apps/output/craton2/*
  rm -rf src/apps/output/kvh1a/*
  rm -rf src/apps/output/x64/*
  rm -rf src/apps/output/x64-debug/*
  rm -rf src/apps/output/hga/*

  # 사용하지 않는 디렉토리 및 소스 제거
  rm -rf src/libs/dot2-2021
  rm -rf src/libs/product/include/dot2-2021
  rm -rf src/libs/depend/ffasn1c/include/ffasn1-dot2-2016.h
  rm -rf src/libs/depend/ffasn1c/lib/kvh1a/libffasn1-dot2-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/x64/libffasn1-dot2-2016.so
  rm -rf src/apps/depend/include/dot3-2020
  rm -rf src/libs/dot3-2020
  rm -rf src/libs/product/include/dot3-2020
  rm -rf src/libs/depend/ffasn1c/include/ffasn1-dot3-2020.h
  rm -rf src/libs/depend/ffasn1c/lib/kvh1a/libffasn1-dot3-2020.so
  rm -rf src/libs/depend/ffasn1c/lib/x64/libffasn1-dot3-2020.so
  rm -rf src/apps/depend/include/dot2-2021
  rm -rf src/libs/depend/dev/SECTON
  rm -rf src/libs/depend/dev/saf5400/0.10
  rm -rf src/libs/depend/dev/saf5400/0.13
  rm -rf test
  rm -rf .cmake
  rm -rf files
  rm -rf v2x-sw.cbp
  rm -rf README.md

  # AES 관련 파일은 삭제하고 직접 추가한다.
  rm -rf src/apps/utils/common/secton-aes
  rm -rf src/libs/ltev2x-hal/src/dev/SECTON/aes.c
  rm -rf src/libs/ltev2x-hal/src/dev/SECTON/aes.h
  rm -rf src/libs/ltev2x-hal/src/dev/SECTON/SECTON-aes.c
  rm -rf scripts/README_RELEASE.txt
}


## libcvcoctci 관련 코드 삭제
delete_libcvcoctci()
{
  # libcvcoctci 라이브러리의 의존 라이브러리 파일들 삭제
  rm -rf src/libs/depend/ffasn1c/include/ffasn1-tci-2017.h
  rm -rf src/libs/depend/ffasn1c/include/ffasn1-tci-2021.h
  rm -rf src/libs/depend/ffasn1c/include/ffasn1-tci-2023.h
  rm -rf src/libs/depend/ffasn1c/lib/condor5/libffasn1-tci-2017.so
  rm -rf src/libs/depend/ffasn1c/lib/condor5/libffasn1-tci-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/condor5/libffasn1-tci-2023.so
  rm -rf src/libs/depend/ffasn1c/lib/condor5v/libffasn1-tci-2017.so
  rm -rf src/libs/depend/ffasn1c/lib/condor5v/libffasn1-tci-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/condor5v/libffasn1-tci-2023.so
  rm -rf src/libs/depend/ffasn1c/lib/condor6/libffasn1-tci-2017.so
  rm -rf src/libs/depend/ffasn1c/lib/condor6/libffasn1-tci-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/condor6/libffasn1-tci-2023.so
  rm -rf src/libs/depend/ffasn1c/lib/craton2/libffasn1-tci-2017.so
  rm -rf src/libs/depend/ffasn1c/lib/craton2/libffasn1-tci-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/craton2/libffasn1-tci-2023.so
  rm -rf src/libs/depend/ffasn1c/lib/kvh1a/libffasn1-tci-2017.so
  rm -rf src/libs/depend/ffasn1c/lib/kvh1a/libffasn1-tci-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/kvh1a/libffasn1-tci-2023.so
  rm -rf src/libs/depend/ffasn1c/lib/x64/libffasn1-tci-2017.so
  rm -rf src/libs/depend/ffasn1c/lib/x64/libffasn1-tci-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/x64/libffasn1-tci-2023.so

  # libcvcoctci 라이브러리 삭제
  rm -rf src/libs/bcvcoctci
  rm -rf src/libs/cvcoctci3
  rm -rf src/libs/cvcoctci-2023
  rm -rf src/libs/product/include/cvcoctci
  rm -rf src/libs/product/include/cvcoctci3
  rm -rf src/libs/product/include/cvcoctci-2023
  rm -rf src/libs/product/bin/condor5/libcvcoctci*
  rm -rf src/libs/product/bin/condor5v/libcvcoctci*
  rm -rf src/libs/product/bin/condor6/libcvcoctci*
  rm -rf src/libs/product/bin/craton2/libcvcoctci*
  rm -rf src/libs/product/bin/kvh1a/libcvcoctci*
  rm -rf src/libs/product/bin/x64/libcvcoctci*
  rm -rf src/libs/product/bin/x64-debug/libcvcoctci*

  # 어플리케이션의 의존 라이브러리(libcvcoctci 라이브러리 포함) 파일들 삭제
  rm -rf src/apps/depend/include/cvcoctci*
  rm -rf src/apps/depend/include/cvcoctci3
  rm -rf src/apps/depend/include/cvcoctci-2023

  # tcia 어플리케이션 삭제
  rm -rf src/apps/output/condor5/tcia*
  rm -rf src/apps/output/condor5v/tcia*
  rm -rf src/apps/output/condor6/tcia*
  rm -rf src/apps/output/craton2/tcia*
  rm -rf src/apps/output/kvh1a/tcia*
}


## libdot2 관련 코드 삭제
delete_libdot2()
{
  # libdot2 라이브러리의 의존 라이브러리 파일들 삭제
  rm -rf src/libs/depend/curl
  rm -rf src/libs/depend/ffasn1c/include/ffasn1-dot2-2021.h
  rm -rf src/libs/depend/ffasn1c/lib/condor5/libffasn1-dot2-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/condor5v/libffasn1-dot2-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/condor6/libffasn1-dot2-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/craton2/libffasn1-dot2-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/kvh1a/libffasn1-dot2-2021.so
  rm -rf src/libs/depend/ffasn1c/lib/x64/libffasn1-dot2-2021.so
  rm -rf src/libs/depend/openssl
  rm -rf src/libs/depend/zip

  # libdot2 라이브러리 삭제
  rm -rf src/libs/dot2*
  rm -rf src/libs/product/include/dot2*
  rm -rf src/libs/product/bin/condor5/libdot2*
  rm -rf src/libs/product/bin/condor5v/libdot2*
  rm -rf src/libs/product/bin/condor6/libdot2*
  rm -rf src/libs/product/bin/craton2/libdot2*
  rm -rf src/libs/product/bin/kvh1a/libdot2*
  rm -rf src/libs/product/bin/x64/libdot2*
  rm -rf src/libs/product/bin/x64-debug/libdot2*

  # 어플리케이션의 의존 라이브러리(libdot2 라이브러리 포함) 파일들 삭제
  rm -rf src/apps/depend/include/dot2*

  # 관련 주요 어플리케이션 파일들 삭제
  rm -rf src/apps/utils/common/app-cert-req
  rm -rf src/apps/utils/common/bootstrap
  rm -rf src/apps/utils/common/cmhf
  rm -rf src/apps/utils/common/crl-req
  rm -rf src/apps/utils/common/id-cert-req
  rm -rf src/apps/utils/common/pseudonym-cert-req
  rm -rf src/apps/utils/common/sec-tester
  rm -rf src/apps/utils/dsrc/sdee-dsrc
  rm -rf src/apps/utils/lte-v2x/sdee-lte-v2x
}


## libdot2 내 scms 관련 코드 삭제
delete_libdot2_scms()
{
  # libdot2 라이브러리 내 scms 관련 코드 삭제
  rm -rf src/libs/dot2-2016/src/api/dot2-api-lcm.c
  rm -rf src/libs/dot2-2016/src/lcm
  rm -rf src/libs/dot2-2016/src/asn1/ffasn1c/lcm
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c/dot2-objasn1c-lcm.c
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c/dot2-objasn1c-lcm-crl.c
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c/dot2-objasn1c-lcm-download.c
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c/dot2-objasn1c-lcm-ecrequest.c
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c/dot2-objasn1c-lcm-ecresponse.c
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c/dot2-objasn1c-lcm-lccf.c
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c/dot2-objasn1c-lcm-provisioning.c
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c/dot2-objasn1c-lcm-provisioning-app-cert.c
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c/dot2-objasn1c-lcm-provisioning-id-cert.c
  rm -rf src/libs/dot2-2016/src/asn1/objasn1c/dot2-objasn1c-lcm-provisioning-pseudonym-cert.c
  rm -rf src/libs/product/bin/condor5/libdot2*
  rm -rf src/libs/product/bin/condor5v/libdot2*
  rm -rf src/libs/product/bin/condor6/libdot2*
  rm -rf src/libs/product/bin/craton2/libdot2*
  rm -rf src/libs/product/bin/kvh1a/libdot2*
  rm -rf src/libs/product/bin/x64/libdot2*
  rm -rf src/libs/product/bin/x64-debug/libdot2*

  # 관련 주요 어플리케이션 파일들 삭제
  rm -rf src/apps/utils/common/app-cert-req
  rm -rf src/apps/utils/common/bootstrap
  rm -rf src/apps/utils/common/crl-req
  rm -rf src/apps/utils/common/id-cert-req
  rm -rf src/apps/utils/common/pseudonym-cert-req
}


## libdot3 관련 코드 삭제
delete_libdot3()
{
  # libdot3 라이브러리의 의존 라이브러리 파일들 삭제
  rm -rf src/libs/depend/ffasn1c/include/ffasn1-dot3-2016.h
  rm -rf src/libs/depend/ffasn1c/lib/condor5/libffasn1-dot3-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/condor5v/libffasn1-dot3-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/condor6/libffasn1-dot3-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/craton2/libffasn1-dot3-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/kvh1a/libffasn1-dot3-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/x64/libffasn1-dot3-2016.so

  # libdot3 라이브러리 삭제
  rm -rf src/libs/dot3*
  rm -rf src/libs/product/include/dot3*
  rm -rf src/libs/product/bin/condor5/libdot3*
  rm -rf src/libs/product/bin/condor5v/libdot3*
  rm -rf src/libs/product/bin/condor6/libdot3*
  rm -rf src/libs/product/bin/craton2/libdot3*
  rm -rf src/libs/product/bin/kvh1a/libdot3*
  rm -rf src/libs/product/bin/x64/libdot3*
  rm -rf src/libs/product/bin/x64-debug/libdot3*

  # 어플리케이션의 의존 라이브러리(libdot3 라이브러리 포함) 파일들 삭제
  rm -rf src/apps/depend/include/dot3*
}


## libj29451 관련 코드 삭제
delete_libj29451()
{
  # libj29451 라이브러리의 의존 라이브러리 파일들 삭제
  rm -rf src/libs/depend/ffasn1c/include/ffasn1-j2735-2016.h
  rm -rf src/libs/depend/ffasn1c/lib/condor5/libffasn1-j2735-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/condor5v/libffasn1-j2735-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/condor6/libffasn1-j2735-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/craton2/libffasn1-j2735-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/kvh1a/libffasn1-j2735-2016.so
  rm -rf src/libs/depend/ffasn1c/lib/x64/libffasn1-j2735-2016.so

  # libj29451 라이브러리 삭제
  rm -rf src/libs/j29451*
  rm -rf src/libs/product/include/j29451*
  rm -rf src/libs/product/bin/condor5/libj29451*
  rm -rf src/libs/product/bin/condor5v/libj29451*
  rm -rf src/libs/product/bin/condor6/libj29451*
  rm -rf src/libs/product/bin/craton2/libj29451*
  rm -rf src/libs/product/bin/kvh1a/libj29451*
  rm -rf src/libs/product/bin/x64/libj29451*
  rm -rf src/libs/product/bin/x64-debug/libj29451*

  # 어플리케이션의 의존 라이브러리(libj29451 라이브러리 포함) 파일들 삭제
  rm -rf src/apps/depend/include/j29451*

  # 관련 주요 어플리케이션 파일들 삭제
  rm -rf src/apps/utils/common/bsmd
}

## libltev2x-hal 관련 코드 삭제
delete_libltev2x_hal() {
  # libltev2x-hal 라이브러리의 의존 라이브러리 파일들 삭제
  rm -rf src/lib/depend/dev/SECTON*

  # libltev2x-hal 라이브러리 삭제
  rm -rf src/libs/ltev2x-hal*
  rm -rf src/libs/product/include/ltev2x-hal*
  rm -rf src/libs/product/bin/condor5/libltev2x-hal*
  rm -rf src/libs/product/bin/condor5v/libltev2x-hal*
  rm -rf src/libs/product/bin/condor6/libltev2x-hal*
  rm -rf src/libs/product/bin/craton2/libltev2x-hal*
  rm -rf src/libs/product/bin/kvh1a/libltev2x-hal*
  rm -rf src/libs/product/bin/kvh1a-debug/libltev2x-hal*
  rm -rf src/libs/product/bin/x64/libltev2x-hal*
  rm -rf src/libs/product/bin/x64-debug/libltev2x-hal*

  # 어플리케이션의 의존 라이브러리(libltev2x-hal 라이브러리 포함) 파일들 삭제
  rm -rf src/apps/depend/include/ltev2x-hal
  rm -rf src/apps/depend/lib/kvh1a/libatlkcli.so*
  rm -rf src/apps/depend/lib/kvh1a/libatlkcv2x.so*
  rm -rf src/apps/depend/lib/kvh1a/libatlkpoti.so*
  rm -rf src/apps/depend/lib/kvh1a/libatlkpotidummy.so*
  rm -rf src/apps/depend/lib/kvh1a/libatlkremote_linux_u.so*
  rm -rf src/apps/depend/lib/kvh1a/libatlksmx.so*
  rm -rf src/apps/depend/lib/kvh1a/libatlktest.so*
  rm -rf src/apps/depend/lib/condor5/liblteaccess*
  rm -rf src/apps/depend/lib/condor5/libcv2x-log.so*
  rm -rf src/apps/depend/lib/condor5/libdsutils.so*
  rm -rf src/apps/depend/lib/condor5/libglib-2.0.so*
  rm -rf src/apps/depend/lib/condor5/libgthread-2.0.so*
  rm -rf src/apps/depend/lib/condor5/libpcre.so*
  rm -rf src/apps/depend/lib/condor5/libqmi*
  rm -rf src/apps/depend/lib/condor5/libtelux*
  rm -rf src/apps/depend/lib/condor5/libv2x_radio.so*
  rm -rf src/apps/depend/lib/condor5v/liblteaccess*
  rm -rf src/apps/depend/lib/condor5v/libcv2x-log.so*
  rm -rf src/apps/depend/lib/condor5v/libdsutils.so*
  rm -rf src/apps/depend/lib/condor5v/libglib-2.0.so*
  rm -rf src/apps/depend/lib/condor5v/libgthread-2.0.so*
  rm -rf src/apps/depend/lib/condor5v/libpcre.so*
  rm -rf src/apps/depend/lib/condor5v/libqmi*
  rm -rf src/apps/depend/lib/condor5v/libtelux*
  rm -rf src/apps/depend/lib/condor5v/libv2x_radio.so*
  rm -rf src/apps/depend/lib/condor6/liblteaccess*
  rm -rf src/apps/depend/lib/condor6/libcv2x-log.so*
  rm -rf src/apps/depend/lib/condor6/libdsutils.so*
  rm -rf src/apps/depend/lib/condor6/libglib-2.0.so*
  rm -rf src/apps/depend/lib/condor6/libgthread-2.0.so*
  rm -rf src/apps/depend/lib/condor6/libpcre.so*
  rm -rf src/apps/depend/lib/condor6/libqmi*
  rm -rf src/apps/depend/lib/condor6/libtelux*
  rm -rf src/apps/depend/lib/condor6/libv2x_radio.so*
  rm -rf src/apps/depend/lib/x64/libltev2x-hal.so*
  rm -rf src/apps/depend/lib/x64-debug/libltev2x-hal.so*

  # 관련 주요 어플리케이션 파일들 삭제
  rm -rf src/apps/utils/ltev2x/ip-ltev2x
  rm -rf src/apps/utils/ltev2x/sdee-ltev2x
  rm -rf src/apps/utils/ltev2x/wsm-ltev2x
  rm -rf src/apps/utils/ltev2x/wsm-test-ltev2x
}

## liblteaccess 관련 코드 삭제
delete_liblteaccess()
{
  # lteaccess 라이브러리의 의존 라이브러리 파일들 삭제
  rm -rf src/libs/depend/dev/ag15

  # lteaccess 라이브러리 삭제
  rm -rf src/libs/lteaccess
  rm -rf src/libs/product/include/lteaccess
  rm -rf src/libs/product/bin/condor5/liblteaccess*
  rm -rf src/libs/product/bin/condor5v/liblteaccess*
  rm -rf src/libs/product/bin/condor6/liblteaccess*
  rm -rf src/libs/product/bin/craton2/liblteaccess*
  rm -rf src/libs/product/bin/x64/liblteaccess*
  rm -rf src/libs/product/bin/x64-debug/liblteaccess*

  # 어플리케이션의 의존 라이브러리(lteaccess 라이브러리 포함) 파일들 삭제
  rm -rf src/apps/depend/include/lteaccess
  rm -rf src/apps/depend/lib/condor5/liblteaccess*
  rm -rf src/apps/depend/lib/condor5/libcv2x-log.so*
  rm -rf src/apps/depend/lib/condor5/libdsutils.so*
  rm -rf src/apps/depend/lib/condor5/libglib-2.0.so*
  rm -rf src/apps/depend/lib/condor5/libgthread-2.0.so*
  rm -rf src/apps/depend/lib/condor5/libpcre.so*
  rm -rf src/apps/depend/lib/condor5/libqmi*
  rm -rf src/apps/depend/lib/condor5/libtelux*
  rm -rf src/apps/depend/lib/condor5/libv2x_radio.so*
  rm -rf src/apps/depend/lib/condor5v/liblteaccess*
  rm -rf src/apps/depend/lib/condor5v/libcv2x-log.so*
  rm -rf src/apps/depend/lib/condor5v/libdsutils.so*
  rm -rf src/apps/depend/lib/condor5v/libglib-2.0.so*
  rm -rf src/apps/depend/lib/condor5v/libgthread-2.0.so*
  rm -rf src/apps/depend/lib/condor5v/libpcre.so*
  rm -rf src/apps/depend/lib/condor5v/libqmi*
  rm -rf src/apps/depend/lib/condor5v/libtelux*
  rm -rf src/apps/depend/lib/condor5v/libv2x_radio.so*
  rm -rf src/apps/depend/lib/condor6/liblteaccess*
  rm -rf src/apps/depend/lib/condor6/libcv2x-log.so*
  rm -rf src/apps/depend/lib/condor6/libdsutils.so*
  rm -rf src/apps/depend/lib/condor6/libglib-2.0.so*
  rm -rf src/apps/depend/lib/condor6/libgthread-2.0.so*
  rm -rf src/apps/depend/lib/condor6/libpcre.so*
  rm -rf src/apps/depend/lib/condor6/libqmi*
  rm -rf src/apps/depend/lib/condor6/libtelux*
  rm -rf src/apps/depend/lib/condor6/libv2x_radio.so*
  rm -rf src/apps/depend/lib/x64/liblteaccess*
  rm -rf src/apps/depend/lib/x64-debug/liblteaccess*
}


## libwlanaccess 관련 코드 삭제
delete_libwlanaccess()
{
  # wlanaccess 라이브러리의 의존 라이브러리 파일들 삭제
  rm -rf src/libs/depend/dev/saf5100
  rm -rf src/libs/depend/dev/saf5400
  rm -rf src/libs/depend/dev/craton2

  # wlanaccess 라이브러리 삭제
  rm -rf src/libs/wlanaccess*
  rm -rf src/libs/product/include/wlanaccess*
  rm -rf src/libs/product/bin/condor5/libwlanaccess*
  rm -rf src/libs/product/bin/condor5v/libwlanaccess*
  rm -rf src/libs/product/bin/condor6/libwlanaccess*
  rm -rf src/libs/product/bin/craton2/libwlanaccess*
  rm -rf src/libs/product/bin/kvh1a/libwlanaccess*
  rm -rf src/libs/product/bin/x64/libwlanaccess*
  rm -rf src/libs/product/bin/x64-debug/libwlanaccess*

  # 어플리케이션의 의존 라이브러리(wlanaccess 라이브러리 포함) 파일들 삭제
  rm -rf src/apps/depend/include/wlanaccess
  rm -rf src/apps/depend/lib/condor5/libwlanaccess*
  rm -rf src/apps/depend/lib/condor5/libLLC*
  rm -rf src/apps/depend/lib/condor5v/libwlanaccess*
  rm -rf src/apps/depend/lib/condor5v/libLLC*
  rm -rf src/apps/depend/lib/condor6/libwlanaccess*
  rm -rf src/apps/depend/lib/condor6/libLLC*
  rm -rf src/apps/depend/lib/craton2/libwlanaccess*
  rm -rf src/apps/depend/lib/craton2/libatlklocal_linux_u.so
  rm -rf src/apps/depend/lib/craton2/libcli.so
  rm -rf src/apps/depend/lib/craton2/libtomcrypt.a
  rm -rf src/apps/depend/lib/craton2/libtommath.a
  rm -rf src/apps/depend/lib/kvh1a/libwlanaccess*
  rm -rf src/apps/depend/lib/kvh1a/libLLC*
  rm -rf src/apps/depend/lib/x64/libwlanaccess*
  rm -rf src/apps/depend/lib/x64-debug/libwlanaccess*

  # 관련 어플리케이션 삭제
  rm -rf src/apps/utils/addr-dsrc
  rm -rf src/apps/utils/chan-dsrc
  rm -rf src/apps/utils/init-dsrc
  rm -rf src/apps/utils/sdee-dsrc
  rm -rf src/apps/utils/wsm-dsrc
}


## Do release
release()
{
  cd ..

  # 공통 부분 삭제
  delete_common

  if [ "$condor" == "n" ]; then
    delete_condor
  fi
  if [ "$craton2" == "n" ]; then
    delete_craton2
  fi
  if [ "$secton" == "n" ]; then
    delete_secton
  fi
  if [ "$ag550q" == "n" ]; then
    delete_ag550q
  fi
  if [ "$libcvcoctci" == "n" ]; then
    delete_libcvcoctci
  fi
  if [ "$libdot2" == "n" ]; then
    delete_libdot2
  fi
  if [ "$libdot2_scms" == "n" ]; then
    delete_libdot2_scms
  fi
  if [ "$libdot3" == "n" ]; then
    delete_libdot3
  fi
  if [ "$libj29451" == "n" ]; then
    delete_libj29451
  fi
  if [ "$liblteaccess" == "n" ]; then
    delete_liblteaccess
  fi
  if [ "$libltev2x_hal" == "n" ]; then
    delete_libltev2x_hal
  fi
  if [ "$libwlanaccess" == "n" ]; then
    delete_libwlanaccess
  fi
  if [ "$eu" == "n" ]; then
    delete_eu
  fi
  if [ "$objasn1c" == "n" ]; then
    delete_objasn1c
  fi
  if [ "$objasn1c_760p" == "n" ]; then
    delete_objasn1c_760p
  fi
  if [ "$objasn1c_744h" == "n" ]; then
    delete_objasn1c_744h
  fi
  if [ "$objasn1c_764t" == "n" ]; then
    delete_objasn1c_764t
  fi
}

release
