/* Automatically generated file - do not edit */
#ifndef _FFASN1_FFASN1_DOT2_2021_H
#define _FFASN1_FFASN1_DOT2_2021_H

#include "asn1defs.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef int dot2Uint16_1;

extern const ASN1CType asn1_type_dot2Uint16_1[];

typedef int dot2Uint8_53;

extern const ASN1CType asn1_type_dot2Uint8_53[];

typedef ASN1String dot2Opaque;

extern const ASN1CType asn1_type_dot2Opaque[];

typedef enum dot2HashAlgorithm {
  dot2HashAlgorithm_sha256,
  dot2HashAlgorithm_sha384,
} dot2HashAlgorithm;

extern const ASN1CType asn1_type_dot2HashAlgorithm[];

typedef enum {
  dot2HashedData_sha256HashedData,
} dot2HashedData_choice;

typedef struct dot2HashedData {
  dot2HashedData_choice choice;
  union {
    ASN1String sha256HashedData;
  } u;
} dot2HashedData;

extern const ASN1CType asn1_type_dot2HashedData[];

typedef struct dot2SignedDataPayload {
  BOOL data_option;
  struct dot2Ieee1609Dot2Data * data;
  BOOL extDataHash_option;
  dot2HashedData extDataHash;
} dot2SignedDataPayload;


extern const ASN1CType asn1_type_dot2SignedDataPayload[];

typedef ASN1Integer dot2Psid;

extern const ASN1CType asn1_type_dot2Psid[];

typedef ASN1Integer dot2Uint64;

extern const ASN1CType asn1_type_dot2Uint64[];

typedef dot2Uint64 dot2Time64;

#define asn1_type_dot2Time64 asn1_type_dot2Uint64

typedef int dot2NinetyDegreeInt;

enum {
  dot2NinetyDegreeInt_min = -900000000,
  dot2NinetyDegreeInt_max = 900000000,
  dot2NinetyDegreeInt_unknown = 900000001,
};

extern const ASN1CType asn1_type_dot2NinetyDegreeInt[];

typedef dot2NinetyDegreeInt dot2Latitude;

extern const ASN1CType asn1_type_dot2Latitude[];

typedef int dot2OneEightyDegreeInt;

enum {
  dot2OneEightyDegreeInt_min = -1799999999,
  dot2OneEightyDegreeInt_max = 1800000000,
  dot2OneEightyDegreeInt_unknown = 1800000001,
};

extern const ASN1CType asn1_type_dot2OneEightyDegreeInt[];

typedef dot2OneEightyDegreeInt dot2Longitude;

extern const ASN1CType asn1_type_dot2Longitude[];

typedef int dot2Uint16;

extern const ASN1CType asn1_type_dot2Uint16[];

typedef dot2Uint16 dot2ElevInt;

#define asn1_type_dot2ElevInt asn1_type_dot2Uint16

typedef dot2ElevInt dot2Elevation;

extern const ASN1CType asn1_type_dot2Elevation[];

typedef struct dot2ThreeDLocation {
  dot2Latitude latitude;
  dot2Longitude longitude;
  dot2Elevation elevation;
} dot2ThreeDLocation;


extern const ASN1CType asn1_type_dot2ThreeDLocation[];

typedef ASN1String dot2HashedId3;

extern const ASN1CType asn1_type_dot2HashedId3[];

typedef dot2Uint16 dot2CrlSeries;

#define asn1_type_dot2CrlSeries asn1_type_dot2Uint16

typedef struct dot2MissingCrlIdentifier {
  dot2HashedId3 cracaId;
  dot2CrlSeries crlSeries;
} dot2MissingCrlIdentifier;


extern const ASN1CType asn1_type_dot2MissingCrlIdentifier[];

typedef enum dot2SymmAlgorithm {
  dot2SymmAlgorithm_aes128Ccm,
} dot2SymmAlgorithm;

extern const ASN1CType asn1_type_dot2SymmAlgorithm[];

typedef struct dot2EccP256CurvePoint_1 {
  ASN1String x;
  ASN1String y;
} dot2EccP256CurvePoint_1;


extern const ASN1CType asn1_type_dot2EccP256CurvePoint_1[];

typedef enum {
  dot2EccP256CurvePoint_x_only,
  dot2EccP256CurvePoint_fill,
  dot2EccP256CurvePoint_compressed_y_0,
  dot2EccP256CurvePoint_compressed_y_1,
  dot2EccP256CurvePoint_uncompressedP256,
} dot2EccP256CurvePoint_choice;

typedef struct dot2EccP256CurvePoint {
  dot2EccP256CurvePoint_choice choice;
  union {
    ASN1String x_only;
    ASN1String compressed_y_0;
    ASN1String compressed_y_1;
    dot2EccP256CurvePoint_1 uncompressedP256;
  } u;
} dot2EccP256CurvePoint;

extern const ASN1CType asn1_type_dot2EccP256CurvePoint[];

typedef enum {
  dot2BasePublicEncryptionKey_eciesNistP256,
  dot2BasePublicEncryptionKey_eciesBrainpoolP256r1,
} dot2BasePublicEncryptionKey_choice;

typedef struct dot2BasePublicEncryptionKey {
  dot2BasePublicEncryptionKey_choice choice;
  union {
    dot2EccP256CurvePoint eciesNistP256;
    dot2EccP256CurvePoint eciesBrainpoolP256r1;
  } u;
} dot2BasePublicEncryptionKey;

extern const ASN1CType asn1_type_dot2BasePublicEncryptionKey[];

typedef struct dot2PublicEncryptionKey {
  dot2SymmAlgorithm supportedSymmAlg;
  dot2BasePublicEncryptionKey publicKey;
} dot2PublicEncryptionKey;


extern const ASN1CType asn1_type_dot2PublicEncryptionKey[];

typedef enum {
  dot2SymmetricEncryptionKey_aes128Ccm,
} dot2SymmetricEncryptionKey_choice;

typedef struct dot2SymmetricEncryptionKey {
  dot2SymmetricEncryptionKey_choice choice;
  union {
    ASN1String aes128Ccm;
  } u;
} dot2SymmetricEncryptionKey;

extern const ASN1CType asn1_type_dot2SymmetricEncryptionKey[];

typedef enum {
  dot2EncryptionKey_Public,
  dot2EncryptionKey_symmetric,
} dot2EncryptionKey_choice;

typedef struct dot2EncryptionKey {
  dot2EncryptionKey_choice choice;
  union {
    dot2PublicEncryptionKey Public;
    dot2SymmetricEncryptionKey symmetric;
  } u;
} dot2EncryptionKey;

extern const ASN1CType asn1_type_dot2EncryptionKey[];

typedef struct dot2SequenceOfHashedId3 {
  dot2HashedId3 *tab;
  size_t count;
} dot2SequenceOfHashedId3;

extern const ASN1CType asn1_type_dot2SequenceOfHashedId3[];

typedef int dot2Uint8_54;

extern const ASN1CType asn1_type_dot2Uint8_54[];

typedef enum dot2CertificateType {
  dot2CertificateType_Explicit,
  dot2CertificateType_implicit,
} dot2CertificateType;

extern const ASN1CType asn1_type_dot2CertificateType[];

typedef ASN1String dot2HashedId8;

extern const ASN1CType asn1_type_dot2HashedId8[];

typedef enum {
  dot2IssuerIdentifier_sha256AndDigest,
  dot2IssuerIdentifier_self,
  dot2IssuerIdentifier_sha384AndDigest,
} dot2IssuerIdentifier_choice;

typedef struct dot2IssuerIdentifier {
  dot2IssuerIdentifier_choice choice;
  union {
    dot2HashedId8 sha256AndDigest;
    dot2HashAlgorithm self;
    dot2HashedId8 sha384AndDigest;
  } u;
} dot2IssuerIdentifier;

extern const ASN1CType asn1_type_dot2IssuerIdentifier[];

typedef dot2Uint16 dot2IValue;

#define asn1_type_dot2IValue asn1_type_dot2Uint16

typedef ASN1String dot2LinkageValue;

extern const ASN1CType asn1_type_dot2LinkageValue[];

typedef struct dot2GroupLinkageValue {
  ASN1String jValue;
  ASN1String value;
} dot2GroupLinkageValue;


extern const ASN1CType asn1_type_dot2GroupLinkageValue[];

typedef struct dot2LinkageData {
  dot2IValue iCert;
  dot2LinkageValue linkage_value;
  BOOL group_linkage_value_option;
  dot2GroupLinkageValue group_linkage_value;
} dot2LinkageData;


extern const ASN1CType asn1_type_dot2LinkageData[];

typedef ASN1String dot2Hostname;

extern const ASN1CType asn1_type_dot2Hostname[];

typedef enum {
  dot2CertificateId_linkageData,
  dot2CertificateId_name,
  dot2CertificateId_binaryId,
  dot2CertificateId_none,
} dot2CertificateId_choice;

typedef struct dot2CertificateId {
  dot2CertificateId_choice choice;
  union {
    dot2LinkageData linkageData;
    dot2Hostname name;
    ASN1String binaryId;
  } u;
} dot2CertificateId;

extern const ASN1CType asn1_type_dot2CertificateId[];

typedef unsigned int dot2Uint32;

extern const ASN1CType asn1_type_dot2Uint32[];

typedef dot2Uint32 dot2Time32;

#define asn1_type_dot2Time32 asn1_type_dot2Uint32

typedef enum {
  dot2Duration_microseconds,
  dot2Duration_milliseconds,
  dot2Duration_seconds,
  dot2Duration_minutes,
  dot2Duration_hours,
  dot2Duration_sixtyHours,
  dot2Duration_years,
} dot2Duration_choice;

typedef struct dot2Duration {
  dot2Duration_choice choice;
  union {
    dot2Uint16 microseconds;
    dot2Uint16 milliseconds;
    dot2Uint16 seconds;
    dot2Uint16 minutes;
    dot2Uint16 hours;
    dot2Uint16 sixtyHours;
    dot2Uint16 years;
  } u;
} dot2Duration;

extern const ASN1CType asn1_type_dot2Duration[];

typedef struct dot2ValidityPeriod {
  dot2Time32 start;
  dot2Duration duration;
} dot2ValidityPeriod;


extern const ASN1CType asn1_type_dot2ValidityPeriod[];

typedef struct dot2TwoDLocation {
  dot2Latitude latitude;
  dot2Longitude longitude;
} dot2TwoDLocation;


extern const ASN1CType asn1_type_dot2TwoDLocation[];

typedef struct dot2CircularRegion {
  dot2TwoDLocation center;
  dot2Uint16 radius;
} dot2CircularRegion;


extern const ASN1CType asn1_type_dot2CircularRegion[];

typedef struct dot2RectangularRegion {
  dot2TwoDLocation northWest;
  dot2TwoDLocation southEast;
} dot2RectangularRegion;


extern const ASN1CType asn1_type_dot2RectangularRegion[];

typedef struct dot2SequenceOfRectangularRegion {
  dot2RectangularRegion *tab;
  size_t count;
} dot2SequenceOfRectangularRegion;

extern const ASN1CType asn1_type_dot2SequenceOfRectangularRegion[];

typedef struct dot2PolygonalRegion {
  dot2TwoDLocation *tab;
  size_t count;
} dot2PolygonalRegion;

extern const ASN1CType asn1_type_dot2PolygonalRegion[];

typedef dot2Uint16 dot2CountryOnly;

#define asn1_type_dot2CountryOnly asn1_type_dot2Uint16

typedef int dot2Uint8;

extern const ASN1CType asn1_type_dot2Uint8[];

typedef struct dot2SequenceOfUint8 {
  dot2Uint8 *tab;
  size_t count;
} dot2SequenceOfUint8;

extern const ASN1CType asn1_type_dot2SequenceOfUint8[];

typedef struct dot2CountryAndRegions {
  dot2CountryOnly countryOnly;
  dot2SequenceOfUint8 regions;
} dot2CountryAndRegions;


extern const ASN1CType asn1_type_dot2CountryAndRegions[];

typedef struct dot2SequenceOfUint16 {
  dot2Uint16 *tab;
  size_t count;
} dot2SequenceOfUint16;

extern const ASN1CType asn1_type_dot2SequenceOfUint16[];

typedef struct dot2RegionAndSubregions {
  dot2Uint8 region;
  dot2SequenceOfUint16 subregions;
} dot2RegionAndSubregions;


extern const ASN1CType asn1_type_dot2RegionAndSubregions[];

typedef struct dot2SequenceOfRegionAndSubregions {
  dot2RegionAndSubregions *tab;
  size_t count;
} dot2SequenceOfRegionAndSubregions;

extern const ASN1CType asn1_type_dot2SequenceOfRegionAndSubregions[];

typedef struct dot2CountryAndSubregions {
  dot2CountryOnly country;
  dot2SequenceOfRegionAndSubregions regionAndSubregions;
} dot2CountryAndSubregions;


extern const ASN1CType asn1_type_dot2CountryAndSubregions[];

typedef enum {
  dot2IdentifiedRegion_countryOnly,
  dot2IdentifiedRegion_countryAndRegions,
  dot2IdentifiedRegion_countryAndSubregions,
} dot2IdentifiedRegion_choice;

typedef struct dot2IdentifiedRegion {
  dot2IdentifiedRegion_choice choice;
  union {
    dot2CountryOnly countryOnly;
    dot2CountryAndRegions countryAndRegions;
    dot2CountryAndSubregions countryAndSubregions;
  } u;
} dot2IdentifiedRegion;

extern const ASN1CType asn1_type_dot2IdentifiedRegion[];

typedef struct dot2SequenceOfIdentifiedRegion {
  dot2IdentifiedRegion *tab;
  size_t count;
} dot2SequenceOfIdentifiedRegion;

extern const ASN1CType asn1_type_dot2SequenceOfIdentifiedRegion[];

typedef enum {
  dot2GeographicRegion_circularRegion,
  dot2GeographicRegion_rectangularRegion,
  dot2GeographicRegion_polygonalRegion,
  dot2GeographicRegion_identifiedRegion,
} dot2GeographicRegion_choice;

typedef struct dot2GeographicRegion {
  dot2GeographicRegion_choice choice;
  union {
    dot2CircularRegion circularRegion;
    dot2SequenceOfRectangularRegion rectangularRegion;
    dot2PolygonalRegion polygonalRegion;
    dot2SequenceOfIdentifiedRegion identifiedRegion;
  } u;
} dot2GeographicRegion;

extern const ASN1CType asn1_type_dot2GeographicRegion[];

typedef ASN1String dot2SubjectAssurance;

extern const ASN1CType asn1_type_dot2SubjectAssurance[];

typedef ASN1String dot2BitmapSsp;

extern const ASN1CType asn1_type_dot2BitmapSsp[];

typedef enum {
  dot2ServiceSpecificPermissions_opaque,
  dot2ServiceSpecificPermissions_bitmapSsp,
} dot2ServiceSpecificPermissions_choice;

typedef struct dot2ServiceSpecificPermissions {
  dot2ServiceSpecificPermissions_choice choice;
  union {
    ASN1String opaque;
    dot2BitmapSsp bitmapSsp;
  } u;
} dot2ServiceSpecificPermissions;

extern const ASN1CType asn1_type_dot2ServiceSpecificPermissions[];

typedef struct dot2PsidSsp {
  dot2Psid psid;
  BOOL ssp_option;
  dot2ServiceSpecificPermissions ssp;
} dot2PsidSsp;


extern const ASN1CType asn1_type_dot2PsidSsp[];

typedef struct dot2SequenceOfPsidSsp {
  dot2PsidSsp *tab;
  size_t count;
} dot2SequenceOfPsidSsp;

extern const ASN1CType asn1_type_dot2SequenceOfPsidSsp[];

typedef struct dot2SequenceOfOctetString {
  ASN1String *tab;
  size_t count;
} dot2SequenceOfOctetString;

extern const ASN1CType asn1_type_dot2SequenceOfOctetString[];

typedef struct dot2BitmapSspRange {
  ASN1String sspValue;
  ASN1String sspBitmask;
} dot2BitmapSspRange;


extern const ASN1CType asn1_type_dot2BitmapSspRange[];

typedef enum {
  dot2SspRange_opaque,
  dot2SspRange_all,
  dot2SspRange_bitmapSspRange,
} dot2SspRange_choice;

typedef struct dot2SspRange {
  dot2SspRange_choice choice;
  union {
    dot2SequenceOfOctetString opaque;
    dot2BitmapSspRange bitmapSspRange;
  } u;
} dot2SspRange;

extern const ASN1CType asn1_type_dot2SspRange[];

typedef struct dot2PsidSspRange {
  dot2Psid psid;
  BOOL sspRange_option;
  dot2SspRange sspRange;
} dot2PsidSspRange;


extern const ASN1CType asn1_type_dot2PsidSspRange[];

typedef struct dot2SequenceOfPsidSspRange {
  dot2PsidSspRange *tab;
  size_t count;
} dot2SequenceOfPsidSspRange;

extern const ASN1CType asn1_type_dot2SequenceOfPsidSspRange[];

typedef enum {
  dot2SubjectPermissions_Explicit,
  dot2SubjectPermissions_all,
} dot2SubjectPermissions_choice;

typedef struct dot2SubjectPermissions {
  dot2SubjectPermissions_choice choice;
  union {
    dot2SequenceOfPsidSspRange Explicit;
  } u;
} dot2SubjectPermissions;

extern const ASN1CType asn1_type_dot2SubjectPermissions[];

typedef ASN1BitString dot2EndEntityType;

extern const ASN1CType asn1_type_dot2EndEntityType[];

typedef struct dot2PsidGroupPermissions {
  dot2SubjectPermissions subjectPermissions;
  ASN1Integer minChainLength;
  ASN1Integer chainLengthRange;
  BOOL eeType_option;
  dot2EndEntityType eeType;
} dot2PsidGroupPermissions;


extern const ASN1CType asn1_type_dot2PsidGroupPermissions[];

typedef struct dot2SequenceOfPsidGroupPermissions {
  dot2PsidGroupPermissions *tab;
  size_t count;
} dot2SequenceOfPsidGroupPermissions;

extern const ASN1CType asn1_type_dot2SequenceOfPsidGroupPermissions[];

typedef struct dot2EccP384CurvePoint_1 {
  ASN1String x;
  ASN1String y;
} dot2EccP384CurvePoint_1;


extern const ASN1CType asn1_type_dot2EccP384CurvePoint_1[];

typedef enum {
  dot2EccP384CurvePoint_x_only,
  dot2EccP384CurvePoint_fill,
  dot2EccP384CurvePoint_compressed_y_0,
  dot2EccP384CurvePoint_compressed_y_1,
  dot2EccP384CurvePoint_uncompressedP384,
} dot2EccP384CurvePoint_choice;

typedef struct dot2EccP384CurvePoint {
  dot2EccP384CurvePoint_choice choice;
  union {
    ASN1String x_only;
    ASN1String compressed_y_0;
    ASN1String compressed_y_1;
    dot2EccP384CurvePoint_1 uncompressedP384;
  } u;
} dot2EccP384CurvePoint;

extern const ASN1CType asn1_type_dot2EccP384CurvePoint[];

typedef enum {
  dot2PublicVerificationKey_ecdsaNistP256,
  dot2PublicVerificationKey_ecdsaBrainpoolP256r1,
  dot2PublicVerificationKey_ecdsaBrainpoolP384r1,
} dot2PublicVerificationKey_choice;

typedef struct dot2PublicVerificationKey {
  dot2PublicVerificationKey_choice choice;
  union {
    dot2EccP256CurvePoint ecdsaNistP256;
    dot2EccP256CurvePoint ecdsaBrainpoolP256r1;
    dot2EccP384CurvePoint ecdsaBrainpoolP384r1;
  } u;
} dot2PublicVerificationKey;

extern const ASN1CType asn1_type_dot2PublicVerificationKey[];

typedef enum {
  dot2VerificationKeyIndicator_verificationKey,
  dot2VerificationKeyIndicator_reconstructionValue,
} dot2VerificationKeyIndicator_choice;

typedef struct dot2VerificationKeyIndicator {
  dot2VerificationKeyIndicator_choice choice;
  union {
    dot2PublicVerificationKey verificationKey;
    dot2EccP256CurvePoint reconstructionValue;
  } u;
} dot2VerificationKeyIndicator;

extern const ASN1CType asn1_type_dot2VerificationKeyIndicator[];

typedef struct dot2ToBeSignedCertificate {
  dot2CertificateId id;
  dot2HashedId3 cracaId;
  dot2CrlSeries crlSeries;
  dot2ValidityPeriod validityPeriod;
  BOOL region_option;
  dot2GeographicRegion region;
  BOOL assuranceLevel_option;
  dot2SubjectAssurance assuranceLevel;
  BOOL appPermissions_option;
  dot2SequenceOfPsidSsp appPermissions;
  BOOL certIssuePermissions_option;
  dot2SequenceOfPsidGroupPermissions certIssuePermissions;
  BOOL certRequestPermissions_option;
  dot2SequenceOfPsidGroupPermissions certRequestPermissions;
  BOOL canRequestRollover_option;
  BOOL encryptionKey_option;
  dot2PublicEncryptionKey encryptionKey;
  dot2VerificationKeyIndicator verifyKeyIndicator;
} dot2ToBeSignedCertificate;


extern const ASN1CType asn1_type_dot2ToBeSignedCertificate[];

typedef struct dot2EcdsaP256Signature {
  dot2EccP256CurvePoint rSig;
  ASN1String sSig;
} dot2EcdsaP256Signature;


extern const ASN1CType asn1_type_dot2EcdsaP256Signature[];

typedef struct dot2EcdsaP384Signature {
  dot2EccP384CurvePoint rSig;
  ASN1String sSig;
} dot2EcdsaP384Signature;


extern const ASN1CType asn1_type_dot2EcdsaP384Signature[];

typedef enum {
  dot2Signature_ecdsaNistP256Signature,
  dot2Signature_ecdsaBrainpoolP256r1Signature,
  dot2Signature_ecdsaBrainpoolP384r1Signature,
} dot2Signature_choice;

typedef struct dot2Signature {
  dot2Signature_choice choice;
  union {
    dot2EcdsaP256Signature ecdsaNistP256Signature;
    dot2EcdsaP256Signature ecdsaBrainpoolP256r1Signature;
    dot2EcdsaP384Signature ecdsaBrainpoolP384r1Signature;
  } u;
} dot2Signature;

extern const ASN1CType asn1_type_dot2Signature[];

typedef struct dot2CertificateBase {
  dot2Uint8_54 version;
  dot2CertificateType type;
  dot2IssuerIdentifier issuer;
  dot2ToBeSignedCertificate toBeSigned;
  BOOL signature_option;
  dot2Signature signature;
} dot2CertificateBase;


extern const ASN1CType asn1_type_dot2CertificateBase[];

typedef dot2CertificateBase dot2Certificate;

#define asn1_type_dot2Certificate asn1_type_dot2CertificateBase

typedef struct dot2HeaderInfo {
  dot2Psid psid;
  BOOL generationTime_option;
  dot2Time64 generationTime;
  BOOL expiryTime_option;
  dot2Time64 expiryTime;
  BOOL generationLocation_option;
  dot2ThreeDLocation generationLocation;
  BOOL p2pcdLearningRequest_option;
  dot2HashedId3 p2pcdLearningRequest;
  BOOL missingCrlIdentifier_option;
  dot2MissingCrlIdentifier missingCrlIdentifier;
  BOOL encryptionKey_option;
  dot2EncryptionKey encryptionKey;
  BOOL inlineP2pcdRequest_option;
  dot2SequenceOfHashedId3 inlineP2pcdRequest;
  BOOL requestedCertificate_option;
  dot2Certificate requestedCertificate;
} dot2HeaderInfo;


extern const ASN1CType asn1_type_dot2HeaderInfo[];

typedef struct dot2ToBeSignedData {
  dot2SignedDataPayload payload;
  dot2HeaderInfo headerInfo;
} dot2ToBeSignedData;


extern const ASN1CType asn1_type_dot2ToBeSignedData[];

typedef struct dot2SequenceOfCertificate {
  dot2Certificate *tab;
  size_t count;
} dot2SequenceOfCertificate;

extern const ASN1CType asn1_type_dot2SequenceOfCertificate[];

typedef enum {
  dot2SignerIdentifier_digest,
  dot2SignerIdentifier_certificate,
  dot2SignerIdentifier_self,
} dot2SignerIdentifier_choice;

typedef struct dot2SignerIdentifier {
  dot2SignerIdentifier_choice choice;
  union {
    dot2HashedId8 digest;
    dot2SequenceOfCertificate certificate;
  } u;
} dot2SignerIdentifier;

extern const ASN1CType asn1_type_dot2SignerIdentifier[];

typedef struct dot2SignedData {
  dot2HashAlgorithm hashId;
  dot2ToBeSignedData tbsData;
  dot2SignerIdentifier signer;
  dot2Signature signature;
} dot2SignedData;


extern const ASN1CType asn1_type_dot2SignedData[];

typedef dot2HashedId8 dot2PreSharedKeyRecipientInfo;

extern const ASN1CType asn1_type_dot2PreSharedKeyRecipientInfo[];

typedef struct dot2AesCcmCiphertext {
  ASN1String nonce;
  dot2Opaque ccmCiphertext;
} dot2AesCcmCiphertext;


extern const ASN1CType asn1_type_dot2AesCcmCiphertext[];

typedef enum {
  dot2SymmetricCiphertext_aes128ccm,
} dot2SymmetricCiphertext_choice;

typedef struct dot2SymmetricCiphertext {
  dot2SymmetricCiphertext_choice choice;
  union {
    dot2AesCcmCiphertext aes128ccm;
  } u;
} dot2SymmetricCiphertext;

extern const ASN1CType asn1_type_dot2SymmetricCiphertext[];

typedef struct dot2SymmRecipientInfo {
  dot2HashedId8 recipientId;
  dot2SymmetricCiphertext encKey;
} dot2SymmRecipientInfo;


extern const ASN1CType asn1_type_dot2SymmRecipientInfo[];

typedef struct dot2EciesP256EncryptedKey {
  dot2EccP256CurvePoint v;
  ASN1String c;
  ASN1String t;
} dot2EciesP256EncryptedKey;


extern const ASN1CType asn1_type_dot2EciesP256EncryptedKey[];

typedef enum {
  dot2EncryptedDataEncryptionKey_eciesNistP256,
  dot2EncryptedDataEncryptionKey_eciesBrainpoolP256r1,
} dot2EncryptedDataEncryptionKey_choice;

typedef struct dot2EncryptedDataEncryptionKey {
  dot2EncryptedDataEncryptionKey_choice choice;
  union {
    dot2EciesP256EncryptedKey eciesNistP256;
    dot2EciesP256EncryptedKey eciesBrainpoolP256r1;
  } u;
} dot2EncryptedDataEncryptionKey;

extern const ASN1CType asn1_type_dot2EncryptedDataEncryptionKey[];

typedef struct dot2PKRecipientInfo {
  dot2HashedId8 recipientId;
  dot2EncryptedDataEncryptionKey encKey;
} dot2PKRecipientInfo;


extern const ASN1CType asn1_type_dot2PKRecipientInfo[];

typedef enum {
  dot2RecipientInfo_pskRecipInfo,
  dot2RecipientInfo_symmRecipInfo,
  dot2RecipientInfo_certRecipInfo,
  dot2RecipientInfo_signedDataRecipInfo,
  dot2RecipientInfo_rekRecipInfo,
} dot2RecipientInfo_choice;

typedef struct dot2RecipientInfo {
  dot2RecipientInfo_choice choice;
  union {
    dot2PreSharedKeyRecipientInfo pskRecipInfo;
    dot2SymmRecipientInfo symmRecipInfo;
    dot2PKRecipientInfo certRecipInfo;
    dot2PKRecipientInfo signedDataRecipInfo;
    dot2PKRecipientInfo rekRecipInfo;
  } u;
} dot2RecipientInfo;

extern const ASN1CType asn1_type_dot2RecipientInfo[];

typedef struct dot2SequenceOfRecipientInfo {
  dot2RecipientInfo *tab;
  size_t count;
} dot2SequenceOfRecipientInfo;

extern const ASN1CType asn1_type_dot2SequenceOfRecipientInfo[];

typedef struct dot2EncryptedData {
  dot2SequenceOfRecipientInfo recipients;
  dot2SymmetricCiphertext ciphertext;
} dot2EncryptedData;


extern const ASN1CType asn1_type_dot2EncryptedData[];

typedef enum {
  dot2Ieee1609Dot2Content_unsecuredData,
  dot2Ieee1609Dot2Content_signedData,
  dot2Ieee1609Dot2Content_encryptedData,
  dot2Ieee1609Dot2Content_signedCertificateRequest,
} dot2Ieee1609Dot2Content_choice;

typedef struct dot2Ieee1609Dot2Content {
  dot2Ieee1609Dot2Content_choice choice;
  union {
    dot2Opaque unsecuredData;
    dot2SignedData signedData;
    dot2EncryptedData encryptedData;
    dot2Opaque signedCertificateRequest;
  } u;
} dot2Ieee1609Dot2Content;

extern const ASN1CType asn1_type_dot2Ieee1609Dot2Content[];

typedef struct dot2Ieee1609Dot2Data {
  dot2Uint8_53 protocolVersion;
  dot2Ieee1609Dot2Content content;
} dot2Ieee1609Dot2Data;


extern const ASN1CType asn1_type_dot2Ieee1609Dot2Data[];

typedef dot2Ieee1609Dot2Data dot2SecuredScmsPDU;

#define asn1_type_dot2SecuredScmsPDU asn1_type_dot2Ieee1609Dot2Data

typedef dot2SecuredScmsPDU dot2SignedElectorEndorsement;

#define asn1_type_dot2SignedElectorEndorsement asn1_type_dot2SecuredScmsPDU

typedef struct dot2ElectorBallot_1 {
  dot2SignedElectorEndorsement *tab;
  size_t count;
} dot2ElectorBallot_1;

extern const ASN1CType asn1_type_dot2ElectorBallot_1[];

typedef struct dot2ElectorBallot {
  dot2ElectorBallot_1 endorsements;
} dot2ElectorBallot;


extern const ASN1CType asn1_type_dot2ElectorBallot[];

typedef struct dot2CertificateStore_1 {
  dot2ElectorBallot *tab;
  size_t count;
} dot2CertificateStore_1;

extern const ASN1CType asn1_type_dot2CertificateStore_1[];

typedef struct dot2CertificateStore_2 {
  dot2ElectorBallot *tab;
  size_t count;
} dot2CertificateStore_2;

extern const ASN1CType asn1_type_dot2CertificateStore_2[];

typedef struct dot2CertificateStore_3 {
  dot2Certificate *tab;
  size_t count;
} dot2CertificateStore_3;

extern const ASN1CType asn1_type_dot2CertificateStore_3[];

typedef struct dot2CertificateStore {
  dot2CertificateStore_1 rootCAEndorsements;
  dot2CertificateStore_2 electorEndorsements;
  dot2Certificate maCertificate;
  dot2CertificateStore_3 certs;
} dot2CertificateStore;


extern const ASN1CType asn1_type_dot2CertificateStore[];

typedef struct dot2GlobalCertificateChainFile {
  dot2Uint16_1 version;
  dot2CertificateStore certStore;
} dot2GlobalCertificateChainFile;


extern const ASN1CType asn1_type_dot2GlobalCertificateChainFile[];

typedef struct dot2CompositeVersion {
  dot2Uint16 gccfVersion;
  dot2Uint16 lccfVersion;
  dot2Hostname raHostname;
} dot2CompositeVersion;


extern const ASN1CType asn1_type_dot2CompositeVersion[];

typedef struct dot2LocalCertificateChainFile_1 {
  dot2Certificate *tab;
  size_t count;
} dot2LocalCertificateChainFile_1;

extern const ASN1CType asn1_type_dot2LocalCertificateChainFile_1[];

typedef struct dot2LocalCertificateChainFile {
  dot2CompositeVersion version;
  dot2CertificateStore requiredCertStore;
  dot2LocalCertificateChainFile_1 optionalCertList;
} dot2LocalCertificateChainFile;


extern const ASN1CType asn1_type_dot2LocalCertificateChainFile[];

typedef enum {
  dot2CertificateChainFiles_globalCertificateChainFile,
  dot2CertificateChainFiles_localCertificateChainFile,
} dot2CertificateChainFiles_choice;

typedef struct dot2CertificateChainFiles {
  dot2CertificateChainFiles_choice choice;
  union {
    dot2GlobalCertificateChainFile globalCertificateChainFile;
    dot2LocalCertificateChainFile localCertificateChainFile;
  } u;
} dot2CertificateChainFiles;

extern const ASN1CType asn1_type_dot2CertificateChainFiles[];

typedef dot2CertificateBase dot2ExplicitCertificate;

#define asn1_type_dot2ExplicitCertificate asn1_type_dot2CertificateBase

typedef dot2ExplicitCertificate dot2CrlgCertificate;

#define asn1_type_dot2CrlgCertificate asn1_type_dot2ExplicitCertificate

typedef dot2ExplicitCertificate dot2DcmCertificate;

#define asn1_type_dot2DcmCertificate asn1_type_dot2ExplicitCertificate

typedef dot2ExplicitCertificate dot2ElectorCertificate;

#define asn1_type_dot2ElectorCertificate asn1_type_dot2ExplicitCertificate

typedef dot2ExplicitCertificate dot2EcaCertificate;

#define asn1_type_dot2EcaCertificate asn1_type_dot2ExplicitCertificate

typedef dot2ExplicitCertificate dot2IcaCertificate;

#define asn1_type_dot2IcaCertificate asn1_type_dot2ExplicitCertificate

typedef dot2ExplicitCertificate dot2LaCertificate;

#define asn1_type_dot2LaCertificate asn1_type_dot2ExplicitCertificate

typedef dot2ExplicitCertificate dot2MaCertificate;

#define asn1_type_dot2MaCertificate asn1_type_dot2ExplicitCertificate

typedef dot2CertificateBase dot2ImplicitCertificate;

#define asn1_type_dot2ImplicitCertificate asn1_type_dot2CertificateBase

typedef dot2ImplicitCertificate dot2ObeEnrollmentCertificate;

#define asn1_type_dot2ObeEnrollmentCertificate asn1_type_dot2ImplicitCertificate

typedef dot2ImplicitCertificate dot2ObeIdentificationCertificate;

#define asn1_type_dot2ObeIdentificationCertificate asn1_type_dot2ImplicitCertificate

typedef dot2ImplicitCertificate dot2ObePseudonymCertificate;

#define asn1_type_dot2ObePseudonymCertificate asn1_type_dot2ImplicitCertificate

typedef dot2ExplicitCertificate dot2PcaCertificate;

#define asn1_type_dot2PcaCertificate asn1_type_dot2ExplicitCertificate

typedef dot2ExplicitCertificate dot2PgCertificate;

#define asn1_type_dot2PgCertificate asn1_type_dot2ExplicitCertificate

typedef dot2ExplicitCertificate dot2RaCertificate;

#define asn1_type_dot2RaCertificate asn1_type_dot2ExplicitCertificate

typedef dot2ExplicitCertificate dot2RootCaCertificate;

#define asn1_type_dot2RootCaCertificate asn1_type_dot2ExplicitCertificate

typedef dot2ImplicitCertificate dot2RseApplicationCertificate;

#define asn1_type_dot2RseApplicationCertificate asn1_type_dot2ImplicitCertificate

typedef dot2ImplicitCertificate dot2RseEnrollmentCertificate;

#define asn1_type_dot2RseEnrollmentCertificate asn1_type_dot2ImplicitCertificate

typedef enum dot2ComponentCertificateManagementError {
  dot2ComponentCertificateManagementError_baseline,
} dot2ComponentCertificateManagementError;

extern const ASN1CType asn1_type_dot2ComponentCertificateManagementError[];

typedef enum dot2EndorsementType {
  dot2EndorsementType_addRoot,
  dot2EndorsementType_addElector,
  dot2EndorsementType_removeRoot,
  dot2EndorsementType_removeElector,
} dot2EndorsementType;

extern const ASN1CType asn1_type_dot2EndorsementType[];

typedef struct dot2TbsElectorEndorsement {
  dot2EndorsementType type;
  dot2ExplicitCertificate certificate;
  BOOL effectiveTime_option;
  dot2Time64 effectiveTime;
} dot2TbsElectorEndorsement;


extern const ASN1CType asn1_type_dot2TbsElectorEndorsement[];

typedef enum {
  dot2ScmsComponentCertificateManagementPDU_tbsElectorEndorsement,
} dot2ScmsComponentCertificateManagementPDU_choice;

typedef struct dot2ScmsComponentCertificateManagementPDU {
  dot2ScmsComponentCertificateManagementPDU_choice choice;
  union {
    dot2TbsElectorEndorsement tbsElectorEndorsement;
  } u;
} dot2ScmsComponentCertificateManagementPDU;

extern const ASN1CType asn1_type_dot2ScmsComponentCertificateManagementPDU[];

typedef dot2Ieee1609Dot2Data dot2SecuredCrl;

#define asn1_type_dot2SecuredCrl asn1_type_dot2Ieee1609Dot2Data

typedef struct dot2CompositeCrl_1 {
  dot2SecuredCrl *tab;
  size_t count;
} dot2CompositeCrl_1;

extern const ASN1CType asn1_type_dot2CompositeCrl_1[];

typedef struct dot2CompositeCrl_2 {
  dot2ElectorBallot *tab;
  size_t count;
} dot2CompositeCrl_2;

extern const ASN1CType asn1_type_dot2CompositeCrl_2[];

typedef struct dot2CompositeCrl_3 {
  dot2ElectorBallot *tab;
  size_t count;
} dot2CompositeCrl_3;

extern const ASN1CType asn1_type_dot2CompositeCrl_3[];

typedef struct dot2CompositeCrl {
  dot2CompositeCrl_1 securedCrlSeries;
  dot2CompositeCrl_2 revokedRootCAs;
  dot2CompositeCrl_3 revokedElectors;
} dot2CompositeCrl;


extern const ASN1CType asn1_type_dot2CompositeCrl[];

typedef enum dot2EcaEndEntityError {
  dot2EcaEndEntityError_ecaInvalidCurrentTime,
  dot2EcaEndEntityError_ecaInvalidRequestedStartTime,
  dot2EcaEndEntityError_ecaInvalidPsid,
  dot2EcaEndEntityError_ecaInvalidValidityPeriod,
  dot2EcaEndEntityError_ecaInvalidRegion,
  dot2EcaEndEntityError_ecaInvalidAssuranceLevel,
  dot2EcaEndEntityError_ecaInvalidEncryptionKey,
  dot2EcaEndEntityError_ecaInvalidVerifyKey,
  dot2EcaEndEntityError_ecaMalformedRequest,
  dot2EcaEndEntityError_ecaInternalServerError,
  dot2EcaEndEntityError_ecaResponseTimeout,
} dot2EcaEndEntityError;

extern const ASN1CType asn1_type_dot2EcaEndEntityError[];

typedef int dot2Uint8_1;

extern const ASN1CType asn1_type_dot2Uint8_1[];

typedef struct dot2EeEcaCertRequest {
  dot2Uint8_1 version;
  dot2Time32 currentTime;
  dot2ToBeSignedCertificate tbsData;
} dot2EeEcaCertRequest;


extern const ASN1CType asn1_type_dot2EeEcaCertRequest[];

typedef int dot2Uint8_2;

extern const ASN1CType asn1_type_dot2Uint8_2[];

typedef ASN1String dot2EccP256PrivateKeyReconstruction;

extern const ASN1CType asn1_type_dot2EccP256PrivateKeyReconstruction[];

typedef struct dot2EcaEeCertResponse {
  dot2Uint8_2 version;
  dot2HashedId8 requestHash;
  dot2Certificate ecaCert;
  dot2ImplicitCertificate enrollmentCert;
  dot2EccP256PrivateKeyReconstruction privKeyReconstruction;
} dot2EcaEeCertResponse;


extern const ASN1CType asn1_type_dot2EcaEeCertResponse[];

typedef enum {
  dot2EcaEndEntityInterfacePDU_eeEcaCertRequest,
  dot2EcaEndEntityInterfacePDU_ecaEeCertResponse,
} dot2EcaEndEntityInterfacePDU_choice;

typedef struct dot2EcaEndEntityInterfacePDU {
  dot2EcaEndEntityInterfacePDU_choice choice;
  union {
    dot2EeEcaCertRequest eeEcaCertRequest;
    dot2EcaEeCertResponse ecaEeCertResponse;
  } u;
} dot2EcaEndEntityInterfacePDU;

extern const ASN1CType asn1_type_dot2EcaEndEntityInterfacePDU[];

typedef int dot2Uint8_3;

extern const ASN1CType asn1_type_dot2Uint8_3[];

typedef struct dot2MisbehaviorReportContents {
  dot2Uint8_3 version;
  dot2Opaque misbehavingDeviceInfo;
  BOOL misbehavingDeviceBSMs_option;
  ASN1String misbehavingDeviceBSMs;
  BOOL reporterDeviceBSMs_option;
  ASN1String reporterDeviceBSMs;
  BOOL sensorInfo_option;
  dot2Opaque sensorInfo;
} dot2MisbehaviorReportContents;


extern const ASN1CType asn1_type_dot2MisbehaviorReportContents[];

typedef enum {
  dot2EndEntityMaInterfacePDU_misbehaviorReport,
} dot2EndEntityMaInterfacePDU_choice;

typedef struct dot2EndEntityMaInterfacePDU {
  dot2EndEntityMaInterfacePDU_choice choice;
  union {
    dot2MisbehaviorReportContents misbehaviorReport;
  } u;
} dot2EndEntityMaInterfacePDU;

extern const ASN1CType asn1_type_dot2EndEntityMaInterfacePDU[];

typedef int dot2Uint8_4;

extern const ASN1CType asn1_type_dot2Uint8_4[];

typedef struct dot2EeRaCertRequestMsg {
  dot2Uint8_4 version;
} dot2EeRaCertRequestMsg;


extern const ASN1CType asn1_type_dot2EeRaCertRequestMsg[];

typedef int dot2Uint8_5;

extern const ASN1CType asn1_type_dot2Uint8_5[];

typedef struct dot2RaEeCertResponseAck {
  dot2Certificate raCertificate;
  dot2CompositeCrl crl;
} dot2RaEeCertResponseAck;


extern const ASN1CType asn1_type_dot2RaEeCertResponseAck[];

typedef enum {
  dot2RaEeCertResponseMsg_1_ack,
} dot2RaEeCertResponseMsg_1_choice;

typedef struct dot2RaEeCertResponseMsg_1 {
  dot2RaEeCertResponseMsg_1_choice choice;
  union {
    dot2RaEeCertResponseAck ack;
  } u;
} dot2RaEeCertResponseMsg_1;

extern const ASN1CType asn1_type_dot2RaEeCertResponseMsg_1[];

typedef struct dot2RaEeCertResponseMsg {
  dot2Uint8_5 version;
  dot2RaEeCertResponseMsg_1 reply;
} dot2RaEeCertResponseMsg;


extern const ASN1CType asn1_type_dot2RaEeCertResponseMsg[];

typedef int dot2Uint8_8;

extern const ASN1CType asn1_type_dot2Uint8_8[];

typedef struct dot2UnsignedButterflyParams {
  dot2EccP256CurvePoint seed_key;
  ASN1String expansion;
} dot2UnsignedButterflyParams;


extern const ASN1CType asn1_type_dot2UnsignedButterflyParams[];

typedef struct dot2CommonProvisioningRequestFields {
  dot2Time32 current_time;
  dot2Time32 requested_start_time;
} dot2CommonProvisioningRequestFields;


extern const ASN1CType asn1_type_dot2CommonProvisioningRequestFields[];

typedef struct dot2EeRaPseudonymCertProvisioningRequest {
  dot2Uint8_8 version;
  dot2UnsignedButterflyParams verify_key_info;
  dot2UnsignedButterflyParams resp_enc_key_info;
  dot2CommonProvisioningRequestFields common;
} dot2EeRaPseudonymCertProvisioningRequest;


extern const ASN1CType asn1_type_dot2EeRaPseudonymCertProvisioningRequest[];

typedef int dot2Uint8_9;

extern const ASN1CType asn1_type_dot2Uint8_9[];

typedef struct dot2PseudonymCertProvisioningAck {
  dot2Time32 certDLTime;
  dot2Hostname certDLURL;
} dot2PseudonymCertProvisioningAck;


extern const ASN1CType asn1_type_dot2PseudonymCertProvisioningAck[];

typedef enum {
  dot2RaEePseudonymCertProvisioningAck_1_ack,
} dot2RaEePseudonymCertProvisioningAck_1_choice;

typedef struct dot2RaEePseudonymCertProvisioningAck_1 {
  dot2RaEePseudonymCertProvisioningAck_1_choice choice;
  union {
    dot2PseudonymCertProvisioningAck ack;
  } u;
} dot2RaEePseudonymCertProvisioningAck_1;

extern const ASN1CType asn1_type_dot2RaEePseudonymCertProvisioningAck_1[];

typedef struct dot2RaEePseudonymCertProvisioningAck {
  dot2Uint8_9 version;
  dot2HashedId8 requestHash;
  dot2RaEePseudonymCertProvisioningAck_1 reply;
} dot2RaEePseudonymCertProvisioningAck;


extern const ASN1CType asn1_type_dot2RaEePseudonymCertProvisioningAck[];

typedef int dot2Uint8_6;

extern const ASN1CType asn1_type_dot2Uint8_6[];

typedef struct dot2EeRaIdCertProvisioningRequest {
  dot2Uint8_6 version;
  dot2UnsignedButterflyParams verify_key_info;
  BOOL cert_enc_key_info_option;
  dot2UnsignedButterflyParams cert_enc_key_info;
  dot2UnsignedButterflyParams resp_enc_key_info;
  dot2CommonProvisioningRequestFields common;
} dot2EeRaIdCertProvisioningRequest;


extern const ASN1CType asn1_type_dot2EeRaIdCertProvisioningRequest[];

typedef dot2RaEePseudonymCertProvisioningAck dot2RaEeIdCertProvisioningAck;

extern const ASN1CType asn1_type_dot2RaEeIdCertProvisioningAck[];

typedef int dot2Uint8_7;

extern const ASN1CType asn1_type_dot2Uint8_7[];

typedef struct dot2EeRaAppCertProvisioningRequest {
  dot2Uint8_7 version;
  dot2PublicVerificationKey verify_key;
  BOOL cert_encryption_key_option;
  dot2PublicEncryptionKey cert_encryption_key;
  dot2PublicEncryptionKey response_encryption_key;
  dot2CommonProvisioningRequestFields common;
} dot2EeRaAppCertProvisioningRequest;


extern const ASN1CType asn1_type_dot2EeRaAppCertProvisioningRequest[];

typedef dot2RaEePseudonymCertProvisioningAck dot2RaEeAppCertProvisioningAck;

extern const ASN1CType asn1_type_dot2RaEeAppCertProvisioningAck[];

typedef struct dot2AuthenticatedDownloadRequest {
  dot2Time32 timestamp;
  ASN1String filename;
} dot2AuthenticatedDownloadRequest;


extern const ASN1CType asn1_type_dot2AuthenticatedDownloadRequest[];

typedef enum {
  dot2EndEntityRaInterfacePDU_eeRaCertRequest,
  dot2EndEntityRaInterfacePDU_raEeCertResponse,
  dot2EndEntityRaInterfacePDU_eeRaPseudonymCertProvisioningRequest,
  dot2EndEntityRaInterfacePDU_raEePseudonymCertProvisioningAck,
  dot2EndEntityRaInterfacePDU_eeRaIdCertProvisioningRequest,
  dot2EndEntityRaInterfacePDU_raEeIdCertProvisioningAck,
  dot2EndEntityRaInterfacePDU_eeRaAppCertProvisioningRequest,
  dot2EndEntityRaInterfacePDU_raEeAppCertProvisioningAck,
  dot2EndEntityRaInterfacePDU_eeRaAuthenticatedDownloadRequest,
} dot2EndEntityRaInterfacePDU_choice;

typedef struct dot2EndEntityRaInterfacePDU {
  dot2EndEntityRaInterfacePDU_choice choice;
  union {
    dot2EeRaCertRequestMsg eeRaCertRequest;
    dot2RaEeCertResponseMsg raEeCertResponse;
    dot2EeRaPseudonymCertProvisioningRequest eeRaPseudonymCertProvisioningRequest;
    dot2RaEePseudonymCertProvisioningAck raEePseudonymCertProvisioningAck;
    dot2EeRaIdCertProvisioningRequest eeRaIdCertProvisioningRequest;
    dot2RaEeIdCertProvisioningAck raEeIdCertProvisioningAck;
    dot2EeRaAppCertProvisioningRequest eeRaAppCertProvisioningRequest;
    dot2RaEeAppCertProvisioningAck raEeAppCertProvisioningAck;
    dot2AuthenticatedDownloadRequest eeRaAuthenticatedDownloadRequest;
  } u;
} dot2EndEntityRaInterfacePDU;

extern const ASN1CType asn1_type_dot2EndEntityRaInterfacePDU[];

typedef dot2ImplicitCertificate dot2EndEntityEnrollmentPseudonymCertificate;

#define asn1_type_dot2EndEntityEnrollmentPseudonymCertificate asn1_type_dot2ImplicitCertificate

typedef enum dot2LaMaBaseErrorCode {
  dot2LaMaBaseErrorCode_laNoMaAuthorizationSignature,
  dot2LaMaBaseErrorCode_laInvalidMaAuthorizationSignature,
  dot2LaMaBaseErrorCode_numberOfRequestsExceeded,
  dot2LaMaBaseErrorCode_noSecureConnectionToRequestor,
  dot2LaMaBaseErrorCode_laInternalTimeout,
  dot2LaMaBaseErrorCode_maRequestTimeout,
  dot2LaMaBaseErrorCode_laInvalidInputValueFormat,
} dot2LaMaBaseErrorCode;

extern const ASN1CType asn1_type_dot2LaMaBaseErrorCode[];

typedef enum dot2LaMaLinkageInfoErrorCode {
  dot2LaMaLinkageInfoErrorCode_atLeastOnePrelinkageValueUnknown,
  dot2LaMaLinkageInfoErrorCode_allPrelinkageValuesUnknown,
  dot2LaMaLinkageInfoErrorCode_onlyOnePrelinkageValuePresented,
  dot2LaMaLinkageInfoErrorCode_laInvalidPrelinkageValuePresented,
} dot2LaMaLinkageInfoErrorCode;

extern const ASN1CType asn1_type_dot2LaMaLinkageInfoErrorCode[];

typedef enum dot2LaMaLinkageSeedErrorCode {
  dot2LaMaLinkageSeedErrorCode_linkageChainIdentifierUnknown,
  dot2LaMaLinkageSeedErrorCode_laInvalidLinkageValue,
  dot2LaMaLinkageSeedErrorCode_laNumberOfLciValuesExceeded,
} dot2LaMaLinkageSeedErrorCode;

extern const ASN1CType asn1_type_dot2LaMaLinkageSeedErrorCode[];

typedef enum {
  dot2LaMaError_la_ma_base_error,
  dot2LaMaError_la_ma_linkage_info_error,
  dot2LaMaError_la_ma_linkage_seed_error,
} dot2LaMaError_choice;

typedef struct dot2LaMaError {
  dot2LaMaError_choice choice;
  union {
    dot2LaMaBaseErrorCode la_ma_base_error;
    dot2LaMaLinkageInfoErrorCode la_ma_linkage_info_error;
    dot2LaMaLinkageSeedErrorCode la_ma_linkage_seed_error;
  } u;
} dot2LaMaError;

extern const ASN1CType asn1_type_dot2LaMaError[];

typedef int dot2Uint8_10;

extern const ASN1CType asn1_type_dot2Uint8_10[];

typedef dot2Hostname dot2MaHostnameId;

extern const ASN1CType asn1_type_dot2MaHostnameId[];

typedef int dot2Uint8_35;

extern const ASN1CType asn1_type_dot2Uint8_35[];

typedef ASN1String dot2LaId;

extern const ASN1CType asn1_type_dot2LaId[];

typedef struct dot2EncryptedIndividualPLV {
  dot2Uint8_35 version;
  dot2LaId laId;
  dot2EncryptedData enc_plv;
} dot2EncryptedIndividualPLV;


extern const ASN1CType asn1_type_dot2EncryptedIndividualPLV[];

typedef struct dot2EncryptedPrelinkageValueAndDontCareFlag {
  dot2EncryptedIndividualPLV encryptedPLV;
  BOOL dontCareFlag;
} dot2EncryptedPrelinkageValueAndDontCareFlag;


extern const ASN1CType asn1_type_dot2EncryptedPrelinkageValueAndDontCareFlag[];

typedef struct dot2ToBeSignedLIRequestMsg_1 {
  dot2EncryptedPrelinkageValueAndDontCareFlag *tab;
  size_t count;
} dot2ToBeSignedLIRequestMsg_1;

extern const ASN1CType asn1_type_dot2ToBeSignedLIRequestMsg_1[];

typedef int dot2Uint8_36;

extern const ASN1CType asn1_type_dot2Uint8_36[];

typedef struct dot2EncryptedGroupPLV {
  dot2Uint8_36 version;
  dot2LaId laId;
  ASN1String encGroupIndex;
  dot2EncryptedData enc_group_plv;
} dot2EncryptedGroupPLV;


extern const ASN1CType asn1_type_dot2EncryptedGroupPLV[];

typedef struct dot2EncryptedGroupPrelinkageValueAndDontCareFlag {
  dot2EncryptedGroupPLV encryptedGroupPLV;
  BOOL dontCareFlag;
} dot2EncryptedGroupPrelinkageValueAndDontCareFlag;


extern const ASN1CType asn1_type_dot2EncryptedGroupPrelinkageValueAndDontCareFlag[];

typedef struct dot2ToBeSignedLIRequestMsg_2 {
  dot2EncryptedGroupPrelinkageValueAndDontCareFlag *tab;
  size_t count;
} dot2ToBeSignedLIRequestMsg_2;

extern const ASN1CType asn1_type_dot2ToBeSignedLIRequestMsg_2[];

typedef enum dot2ExpectedReply {
  dot2ExpectedReply_scalarAnswer,
  dot2ExpectedReply_indicesLists,
} dot2ExpectedReply;

extern const ASN1CType asn1_type_dot2ExpectedReply[];

typedef struct dot2ToBeSignedLIRequestMsg {
  dot2MaHostnameId maId;
  dot2ToBeSignedLIRequestMsg_1 encryptedPLVsAndFlags;
  dot2ToBeSignedLIRequestMsg_2 encryptedGPLVsAndFlags;
  dot2ExpectedReply expectedReply;
} dot2ToBeSignedLIRequestMsg;


extern const ASN1CType asn1_type_dot2ToBeSignedLIRequestMsg[];

typedef dot2Ieee1609Dot2Data dot2Countersignature;

#define asn1_type_dot2Countersignature asn1_type_dot2Ieee1609Dot2Data

typedef struct dot2MaLaLinkageInfoRequestMsg_1 {
  dot2Countersignature *tab;
  size_t count;
} dot2MaLaLinkageInfoRequestMsg_1;

extern const ASN1CType asn1_type_dot2MaLaLinkageInfoRequestMsg_1[];

typedef struct dot2MaLaLinkageInfoRequestMsg {
  dot2Uint8_10 version;
  dot2ToBeSignedLIRequestMsg tbs;
  dot2MaLaLinkageInfoRequestMsg_1 signatures;
} dot2MaLaLinkageInfoRequestMsg;


extern const ASN1CType asn1_type_dot2MaLaLinkageInfoRequestMsg[];

typedef int dot2Uint8_11;

extern const ASN1CType asn1_type_dot2Uint8_11[];

typedef dot2Hostname dot2LaHostnameId;

#define asn1_type_dot2LaHostnameId asn1_type_dot2Hostname

typedef struct dot2LinkageInformation_1 {
  ASN1Integer matches;
  BOOL lowerBound;
} dot2LinkageInformation_1;


extern const ASN1CType asn1_type_dot2LinkageInformation_1[];

typedef ASN1String dot2PreLinkageValue;

extern const ASN1CType asn1_type_dot2PreLinkageValue[];

typedef struct dot2LinkageInformation_2 {
  dot2PreLinkageValue *tab;
  size_t count;
} dot2LinkageInformation_2;

extern const ASN1CType asn1_type_dot2LinkageInformation_2[];

typedef struct dot2LinkageInformation_3 {
  dot2PreLinkageValue *tab;
  size_t count;
} dot2LinkageInformation_3;

extern const ASN1CType asn1_type_dot2LinkageInformation_3[];

typedef struct dot2LinkageInformation_4 {
  dot2PreLinkageValue *tab;
  size_t count;
} dot2LinkageInformation_4;

extern const ASN1CType asn1_type_dot2LinkageInformation_4[];

typedef struct dot2LinkageInformation_5 {
  dot2LinkageInformation_4 *tab;
  size_t count;
} dot2LinkageInformation_5;

extern const ASN1CType asn1_type_dot2LinkageInformation_5[];

typedef struct dot2LinkageInformation_6 {
  dot2LinkageInformation_2 unkownPlv;
  dot2LinkageInformation_3 rejectPlv;
  dot2LinkageInformation_5 assocPlv;
} dot2LinkageInformation_6;


extern const ASN1CType asn1_type_dot2LinkageInformation_6[];

typedef enum {
  dot2LinkageInformation_scalar,
  dot2LinkageInformation_indicesList,
} dot2LinkageInformation_choice;

typedef struct dot2LinkageInformation {
  dot2LinkageInformation_choice choice;
  union {
    dot2LinkageInformation_1 scalar;
    dot2LinkageInformation_6 indicesList;
  } u;
} dot2LinkageInformation;

extern const ASN1CType asn1_type_dot2LinkageInformation[];

typedef enum dot2ScmsCommonError {
  dot2ScmsCommonError_baseline,
} dot2ScmsCommonError;

extern const ASN1CType asn1_type_dot2ScmsCommonError[];

typedef enum dot2LaPcaErrorCode {
  dot2LaPcaErrorCode_invalidSignature,
  dot2LaPcaErrorCode_invalidCertificate,
  dot2LaPcaErrorCode_invalidStartTime,
  dot2LaPcaErrorCode_invalidEndTime,
  dot2LaPcaErrorCode_invalidAlgorithm,
  dot2LaPcaErrorCode_invalidMacValue,
} dot2LaPcaErrorCode;

extern const ASN1CType asn1_type_dot2LaPcaErrorCode[];

typedef enum {
  dot2LaPcaError_la_pca,
} dot2LaPcaError_choice;

typedef struct dot2LaPcaError {
  dot2LaPcaError_choice choice;
  union {
    dot2LaPcaErrorCode la_pca;
  } u;
} dot2LaPcaError;

extern const ASN1CType asn1_type_dot2LaPcaError[];

typedef enum dot2LaRaErrorCode {
  dot2LaRaErrorCode_invalidPcaKey,
  dot2LaRaErrorCode_invalidIMin,
  dot2LaRaErrorCode_invalidIMax,
  dot2LaRaErrorCode_invalidContinueChain,
  dot2LaRaErrorCode_invalidLinkagechainId,
  dot2LaRaErrorCode_invalidJMax,
} dot2LaRaErrorCode;

extern const ASN1CType asn1_type_dot2LaRaErrorCode[];

typedef enum {
  dot2LaRaError_la_ra,
} dot2LaRaError_choice;

typedef struct dot2LaRaError {
  dot2LaRaError_choice choice;
  union {
    dot2LaRaErrorCode la_ra;
  } u;
} dot2LaRaError;

extern const ASN1CType asn1_type_dot2LaRaError[];

typedef enum dot2MaPcaErrorCode {
  dot2MaPcaErrorCode_pcaInternalTimeout,
  dot2MaPcaErrorCode_maRequestTimeout,
  dot2MaPcaErrorCode_pcaNoMaAuthorizationSignature,
  dot2MaPcaErrorCode_pcaInvalidMaAuthorizationSignature,
  dot2MaPcaErrorCode_numberofRequestsExceeded,
  dot2MaPcaErrorCode_pcaNumberOfLinkageValuesExceeded,
  dot2MaPcaErrorCode_noSecureConnectiontoRequestor,
  dot2MaPcaErrorCode_tooManyUsers,
  dot2MaPcaErrorCode_linkageValueUnknown,
  dot2MaPcaErrorCode_pcaInvalidLinkageValue,
  dot2MaPcaErrorCode_pcaInvalidInputValueFormat,
} dot2MaPcaErrorCode;

extern const ASN1CType asn1_type_dot2MaPcaErrorCode[];

typedef enum {
  dot2MaPcaError_ma_pca,
} dot2MaPcaError_choice;

typedef struct dot2MaPcaError {
  dot2MaPcaError_choice choice;
  union {
    dot2MaPcaErrorCode ma_pca;
  } u;
} dot2MaPcaError;

extern const ASN1CType asn1_type_dot2MaPcaError[];

typedef enum dot2MaRaBaseErrorCode {
  dot2MaRaBaseErrorCode_raInternalTimeout,
  dot2MaRaBaseErrorCode_maRequestTimeout,
  dot2MaRaBaseErrorCode_raNoMaAuthorizationSignature,
  dot2MaRaBaseErrorCode_raInvalidMaAuthorizationSignature,
  dot2MaRaBaseErrorCode_raInvalidInputValueFormat,
  dot2MaRaBaseErrorCode_raInvalidHashRequest,
  dot2MaRaBaseErrorCode_raInvalidRIFValue,
  dot2MaRaBaseErrorCode_raInvalidLinkageValue,
  dot2MaRaBaseErrorCode_raNumberOfRequestsExceeded,
  dot2MaRaBaseErrorCode_noSecureConnectionToRequestor,
  dot2MaRaBaseErrorCode_hpcrIsUnknownToRA,
} dot2MaRaBaseErrorCode;

extern const ASN1CType asn1_type_dot2MaRaBaseErrorCode[];

typedef enum dot2MaRaBlacklistErrorCode {
  dot2MaRaBlacklistErrorCode_alreadyBlacklisted,
} dot2MaRaBlacklistErrorCode;

extern const ASN1CType asn1_type_dot2MaRaBlacklistErrorCode[];

typedef enum dot2MaRaLCIErrorCode {
  dot2MaRaLCIErrorCode_noLinkageChainIdentifiersKnownForHPCR,
} dot2MaRaLCIErrorCode;

extern const ASN1CType asn1_type_dot2MaRaLCIErrorCode[];

typedef enum dot2MaRaCDVErrorCode {
  dot2MaRaCDVErrorCode_noCertificateDigestValuesKnownForRIF,
} dot2MaRaCDVErrorCode;

extern const ASN1CType asn1_type_dot2MaRaCDVErrorCode[];

typedef enum {
  dot2MaRaError_ma_ra_base_error,
  dot2MaRaError_ma_ra_blacklist_error,
  dot2MaRaError_ma_ra_lci_error,
  dot2MaRaError_ma_ra_cdv_error,
} dot2MaRaError_choice;

typedef struct dot2MaRaError {
  dot2MaRaError_choice choice;
  union {
    dot2MaRaBaseErrorCode ma_ra_base_error;
    dot2MaRaBlacklistErrorCode ma_ra_blacklist_error;
    dot2MaRaLCIErrorCode ma_ra_lci_error;
    dot2MaRaCDVErrorCode ma_ra_cdv_error;
  } u;
} dot2MaRaError;

extern const ASN1CType asn1_type_dot2MaRaError[];

typedef enum dot2PcaRaBaseErrorCode {
  dot2PcaRaBaseErrorCode_unknownError,
} dot2PcaRaBaseErrorCode;

extern const ASN1CType asn1_type_dot2PcaRaBaseErrorCode[];

typedef enum dot2PcaRaRequestErrorCode {
  dot2PcaRaRequestErrorCode_invalidCertificateRequestType,
  dot2PcaRaRequestErrorCode_invalidType,
  dot2PcaRaRequestErrorCode_invalidPsidSsp,
  dot2PcaRaRequestErrorCode_invalidRegion,
  dot2PcaRaRequestErrorCode_invalidValidity,
  dot2PcaRaRequestErrorCode_invalidEncryptionPublicKey,
  dot2PcaRaRequestErrorCode_invalidSignaturePublicKey,
  dot2PcaRaRequestErrorCode_invalidEncryptedPreLinkageValue,
  dot2PcaRaRequestErrorCode_invalidEncryptedGroupPreLinkageValue,
} dot2PcaRaRequestErrorCode;

extern const ASN1CType asn1_type_dot2PcaRaRequestErrorCode[];

typedef enum {
  dot2PcaRaError_pca_ra_base_error,
  dot2PcaRaError_pca_ra_request_error,
} dot2PcaRaError_choice;

typedef struct dot2PcaRaError {
  dot2PcaRaError_choice choice;
  union {
    dot2PcaRaBaseErrorCode pca_ra_base_error;
    dot2PcaRaRequestErrorCode pca_ra_request_error;
  } u;
} dot2PcaRaError;

extern const ASN1CType asn1_type_dot2PcaRaError[];

typedef enum {
  dot2ScmsError_common,
  dot2ScmsError_ccm,
  dot2ScmsError_eca_ee,
  dot2ScmsError_la_ma,
  dot2ScmsError_la_pca,
  dot2ScmsError_la_ra,
  dot2ScmsError_ma_pca,
  dot2ScmsError_ma_ra,
  dot2ScmsError_pca_ra,
} dot2ScmsError_choice;

typedef struct dot2ScmsError {
  dot2ScmsError_choice choice;
  union {
    dot2ScmsCommonError common;
    dot2ComponentCertificateManagementError ccm;
    dot2EcaEndEntityError eca_ee;
    dot2LaMaError la_ma;
    dot2LaPcaError la_pca;
    dot2LaRaError la_ra;
    dot2MaPcaError ma_pca;
    dot2MaRaError ma_ra;
    dot2PcaRaError pca_ra;
  } u;
} dot2ScmsError;

extern const ASN1CType asn1_type_dot2ScmsError[];

typedef dot2ScmsError dot2ScopedLaMaLIError;

#define asn1_type_dot2ScopedLaMaLIError asn1_type_dot2ScmsError

typedef enum {
  dot2LaMaLinkageInfoResponseMsg_1_success,
  dot2LaMaLinkageInfoResponseMsg_1_failure,
} dot2LaMaLinkageInfoResponseMsg_1_choice;

typedef struct dot2LaMaLinkageInfoResponseMsg_1 {
  dot2LaMaLinkageInfoResponseMsg_1_choice choice;
  union {
    dot2LinkageInformation success;
    dot2ScopedLaMaLIError failure;
  } u;
} dot2LaMaLinkageInfoResponseMsg_1;

extern const ASN1CType asn1_type_dot2LaMaLinkageInfoResponseMsg_1[];

typedef struct dot2LaMaLinkageInfoResponseMsg {
  dot2Uint8_11 version;
  dot2HashedId8 requestHash;
  dot2LaHostnameId laId;
  dot2LaMaLinkageInfoResponseMsg_1 linkageInfo;
} dot2LaMaLinkageInfoResponseMsg;


extern const ASN1CType asn1_type_dot2LaMaLinkageInfoResponseMsg[];

typedef int dot2Uint8_12;

extern const ASN1CType asn1_type_dot2Uint8_12[];

typedef dot2EncryptedData dot2LinkageChainId;

#define asn1_type_dot2LinkageChainId asn1_type_dot2EncryptedData

typedef struct dot2ToBeSignedLSRequestMsg_1 {
  dot2LinkageChainId *tab;
  size_t count;
} dot2ToBeSignedLSRequestMsg_1;

extern const ASN1CType asn1_type_dot2ToBeSignedLSRequestMsg_1[];

typedef struct dot2ToBeSignedLSRequestMsg {
  dot2MaHostnameId maId;
  dot2ToBeSignedLSRequestMsg_1 lci;
} dot2ToBeSignedLSRequestMsg;


extern const ASN1CType asn1_type_dot2ToBeSignedLSRequestMsg[];

typedef struct dot2MaLaLinkageSeedRequestMsg_1 {
  dot2Countersignature *tab;
  size_t count;
} dot2MaLaLinkageSeedRequestMsg_1;

extern const ASN1CType asn1_type_dot2MaLaLinkageSeedRequestMsg_1[];

typedef struct dot2MaLaLinkageSeedRequestMsg {
  dot2Uint8_12 version;
  dot2ToBeSignedLSRequestMsg tbs;
  dot2MaLaLinkageSeedRequestMsg_1 signatures;
} dot2MaLaLinkageSeedRequestMsg;


extern const ASN1CType asn1_type_dot2MaLaLinkageSeedRequestMsg[];

typedef int dot2Uint8_13;

extern const ASN1CType asn1_type_dot2Uint8_13[];

typedef ASN1String dot2LinkageSeed;

extern const ASN1CType asn1_type_dot2LinkageSeed[];

typedef struct dot2LinkageSeedAndLaId {
  dot2LinkageSeed linkageSeed;
  dot2LaId laId;
} dot2LinkageSeedAndLaId;


extern const ASN1CType asn1_type_dot2LinkageSeedAndLaId[];

typedef dot2ScmsError dot2ScopedLaMaLSError;

#define asn1_type_dot2ScopedLaMaLSError asn1_type_dot2ScmsError

typedef enum {
  dot2LCI2LS_1_success,
  dot2LCI2LS_1_failure,
} dot2LCI2LS_1_choice;

typedef struct dot2LCI2LS_1 {
  dot2LCI2LS_1_choice choice;
  union {
    dot2LinkageSeedAndLaId success;
    dot2ScopedLaMaLSError failure;
  } u;
} dot2LCI2LS_1;

extern const ASN1CType asn1_type_dot2LCI2LS_1[];

typedef struct dot2LCI2LS {
  dot2LinkageChainId lci;
  dot2LCI2LS_1 reply;
} dot2LCI2LS;


extern const ASN1CType asn1_type_dot2LCI2LS[];

typedef struct dot2LaMaLinkageSeedResponseMsg_1 {
  dot2LCI2LS *tab;
  size_t count;
} dot2LaMaLinkageSeedResponseMsg_1;

extern const ASN1CType asn1_type_dot2LaMaLinkageSeedResponseMsg_1[];

typedef struct dot2LaMaLinkageSeedResponseMsg {
  dot2Uint8_13 version;
  dot2HashedId8 requestHash;
  dot2LaHostnameId laId;
  dot2LaMaLinkageSeedResponseMsg_1 lsInfo;
} dot2LaMaLinkageSeedResponseMsg;


extern const ASN1CType asn1_type_dot2LaMaLinkageSeedResponseMsg[];

typedef enum {
  dot2LaMaInterfacePDU_maLaLinkageInfoRequest,
  dot2LaMaInterfacePDU_laMaLinkageInfoResponse,
  dot2LaMaInterfacePDU_maLaLinkageSeedRequest,
  dot2LaMaInterfacePDU_laMaLinkageSeedResponse,
} dot2LaMaInterfacePDU_choice;

typedef struct dot2LaMaInterfacePDU {
  dot2LaMaInterfacePDU_choice choice;
  union {
    dot2MaLaLinkageInfoRequestMsg maLaLinkageInfoRequest;
    dot2LaMaLinkageInfoResponseMsg laMaLinkageInfoResponse;
    dot2MaLaLinkageSeedRequestMsg maLaLinkageSeedRequest;
    dot2LaMaLinkageSeedResponseMsg laMaLinkageSeedResponse;
  } u;
} dot2LaMaInterfacePDU;

extern const ASN1CType asn1_type_dot2LaMaInterfacePDU[];

typedef int dot2Uint8_14;

extern const ASN1CType asn1_type_dot2Uint8_14[];

typedef dot2Hostname dot2PcaHostnameId;

#define asn1_type_dot2PcaHostnameId asn1_type_dot2Hostname

typedef struct dot2PcaLaKeyAgreementRequestMsg {
  dot2Uint8_14 version;
  dot2PcaHostnameId pcaId;
  BOOL pcaCertificate_option;
  dot2Certificate pcaCertificate;
  dot2EncryptedData enc_R_pca;
  dot2Time32 startDate;
  dot2Time32 endDate;
} dot2PcaLaKeyAgreementRequestMsg;


extern const ASN1CType asn1_type_dot2PcaLaKeyAgreementRequestMsg[];

typedef int dot2Uint8_15;

extern const ASN1CType asn1_type_dot2Uint8_15[];

typedef ASN1String dot2FullSizeHash;

extern const ASN1CType asn1_type_dot2FullSizeHash[];

typedef dot2ScmsError dot2ScopedLaPcaError;

#define asn1_type_dot2ScopedLaPcaError asn1_type_dot2ScmsError

typedef enum {
  dot2LaPcaKeyAgreementResponseMsg_1_success,
  dot2LaPcaKeyAgreementResponseMsg_1_failure,
} dot2LaPcaKeyAgreementResponseMsg_1_choice;

typedef struct dot2LaPcaKeyAgreementResponseMsg_1 {
  dot2LaPcaKeyAgreementResponseMsg_1_choice choice;
  union {
    dot2FullSizeHash success;
    dot2ScopedLaPcaError failure;
  } u;
} dot2LaPcaKeyAgreementResponseMsg_1;

extern const ASN1CType asn1_type_dot2LaPcaKeyAgreementResponseMsg_1[];

typedef struct dot2LaPcaKeyAgreementResponseMsg {
  dot2Uint8_15 version;
  dot2HashedId8 requestHash;
  dot2LaHostnameId laId;
  dot2EncryptedData enc_R_la;
  dot2LaPcaKeyAgreementResponseMsg_1 reply;
} dot2LaPcaKeyAgreementResponseMsg;


extern const ASN1CType asn1_type_dot2LaPcaKeyAgreementResponseMsg[];

typedef int dot2Uint8_16;

extern const ASN1CType asn1_type_dot2Uint8_16[];

typedef enum {
  dot2PcaLaKeyAgreementAckMsg_1_success,
  dot2PcaLaKeyAgreementAckMsg_1_failure,
} dot2PcaLaKeyAgreementAckMsg_1_choice;

typedef struct dot2PcaLaKeyAgreementAckMsg_1 {
  dot2PcaLaKeyAgreementAckMsg_1_choice choice;
  union {
    dot2FullSizeHash success;
    dot2ScopedLaPcaError failure;
  } u;
} dot2PcaLaKeyAgreementAckMsg_1;

extern const ASN1CType asn1_type_dot2PcaLaKeyAgreementAckMsg_1[];

typedef struct dot2PcaLaKeyAgreementAckMsg {
  dot2Uint8_16 version;
  dot2HashedId8 requestHash;
  dot2PcaHostnameId pcaId;
  dot2PcaLaKeyAgreementAckMsg_1 reply;
} dot2PcaLaKeyAgreementAckMsg;


extern const ASN1CType asn1_type_dot2PcaLaKeyAgreementAckMsg[];

typedef enum {
  dot2LaPcaInterfacePDU_pcaLaKeyAgreementRequest,
  dot2LaPcaInterfacePDU_laPcaKeyAgreementResponse,
  dot2LaPcaInterfacePDU_pcaLaKeyAgreementAck,
} dot2LaPcaInterfacePDU_choice;

typedef struct dot2LaPcaInterfacePDU {
  dot2LaPcaInterfacePDU_choice choice;
  union {
    dot2PcaLaKeyAgreementRequestMsg pcaLaKeyAgreementRequest;
    dot2LaPcaKeyAgreementResponseMsg laPcaKeyAgreementResponse;
    dot2PcaLaKeyAgreementAckMsg pcaLaKeyAgreementAck;
  } u;
} dot2LaPcaInterfacePDU;

extern const ASN1CType asn1_type_dot2LaPcaInterfacePDU[];

typedef ASN1String dot2PcaRandomContribution;

extern const ASN1CType asn1_type_dot2PcaRandomContribution[];

typedef ASN1String dot2LaRandomContribution;

extern const ASN1CType asn1_type_dot2LaRandomContribution[];

typedef int dot2Uint8_17;

extern const ASN1CType asn1_type_dot2Uint8_17[];

typedef dot2Hostname dot2RaHostnameId;

#define asn1_type_dot2RaHostnameId asn1_type_dot2Hostname

typedef struct dot2RaLaPreLinkageValueRequestMsgHeader {
  dot2Uint8_17 version;
  dot2RaHostnameId raId;
  dot2PcaHostnameId pcaId;
  dot2Uint16 iMin;
  dot2Uint16 iMax;
} dot2RaLaPreLinkageValueRequestMsgHeader;


extern const ASN1CType asn1_type_dot2RaLaPreLinkageValueRequestMsgHeader[];

typedef struct dot2RaLaIndividualPreLinkageValueRequestMsg_1 {
  dot2LinkageChainId *tab;
  size_t count;
} dot2RaLaIndividualPreLinkageValueRequestMsg_1;

extern const ASN1CType asn1_type_dot2RaLaIndividualPreLinkageValueRequestMsg_1[];

typedef struct dot2RaLaIndividualPreLinkageValueRequestMsg {
  dot2RaLaPreLinkageValueRequestMsgHeader header;
  dot2Uint8 jMax;
  BOOL numberOfFreshInd_option;
  dot2Uint32 numberOfFreshInd;
  BOOL continuationsInd_option;
  dot2RaLaIndividualPreLinkageValueRequestMsg_1 continuationsInd;
} dot2RaLaIndividualPreLinkageValueRequestMsg;


extern const ASN1CType asn1_type_dot2RaLaIndividualPreLinkageValueRequestMsg[];

typedef struct dot2RaLaGroupPreLinkageValueRequestMsg {
  dot2RaLaPreLinkageValueRequestMsgHeader header;
  dot2Uint32 jMax;
  dot2LaId otherLa;
  ASN1String groupIdentifier;
} dot2RaLaGroupPreLinkageValueRequestMsg;


extern const ASN1CType asn1_type_dot2RaLaGroupPreLinkageValueRequestMsg[];

typedef int dot2Uint8_18;

extern const ASN1CType asn1_type_dot2Uint8_18[];

typedef struct dot2IndividualPlvResponseLinkageChain_1 {
  dot2EncryptedIndividualPLV *tab;
  size_t count;
} dot2IndividualPlvResponseLinkageChain_1;

extern const ASN1CType asn1_type_dot2IndividualPlvResponseLinkageChain_1[];

typedef struct dot2IndividualPlvResponseLinkageChain_2 {
  dot2IndividualPlvResponseLinkageChain_1 *tab;
  size_t count;
} dot2IndividualPlvResponseLinkageChain_2;

extern const ASN1CType asn1_type_dot2IndividualPlvResponseLinkageChain_2[];

typedef struct dot2IndividualPlvResponseLinkageChain {
  dot2Uint8 jMax;
  dot2IndividualPlvResponseLinkageChain_2 values;
  dot2LinkageChainId linkageChainId;
} dot2IndividualPlvResponseLinkageChain;


extern const ASN1CType asn1_type_dot2IndividualPlvResponseLinkageChain[];

typedef struct dot2PreLinkageValueRequestResponse_1 {
  dot2IndividualPlvResponseLinkageChain *tab;
  size_t count;
} dot2PreLinkageValueRequestResponse_1;

extern const ASN1CType asn1_type_dot2PreLinkageValueRequestResponse_1[];

typedef struct dot2GroupPlvResponseLinkageChain_1 {
  dot2EncryptedGroupPLV *tab;
  size_t count;
} dot2GroupPlvResponseLinkageChain_1;

extern const ASN1CType asn1_type_dot2GroupPlvResponseLinkageChain_1[];

typedef struct dot2GroupPlvResponseLinkageChain_2 {
  dot2GroupPlvResponseLinkageChain_1 *tab;
  size_t count;
} dot2GroupPlvResponseLinkageChain_2;

extern const ASN1CType asn1_type_dot2GroupPlvResponseLinkageChain_2[];

typedef struct dot2GroupPlvResponseLinkageChain {
  dot2Uint32 jMax;
  dot2LaId otherLa;
  dot2GroupPlvResponseLinkageChain_2 values;
  ASN1String groupIdentifier;
} dot2GroupPlvResponseLinkageChain;


extern const ASN1CType asn1_type_dot2GroupPlvResponseLinkageChain[];

typedef struct dot2PreLinkageValueRequestResponse_2 {
  dot2GroupPlvResponseLinkageChain *tab;
  size_t count;
} dot2PreLinkageValueRequestResponse_2;

extern const ASN1CType asn1_type_dot2PreLinkageValueRequestResponse_2[];

typedef struct dot2PreLinkageValueRequestResponse {
  dot2Uint16 iMin;
  dot2Uint16 iMax;
  dot2PreLinkageValueRequestResponse_1 individual;
  dot2PreLinkageValueRequestResponse_2 group;
} dot2PreLinkageValueRequestResponse;


extern const ASN1CType asn1_type_dot2PreLinkageValueRequestResponse[];

typedef dot2ScmsError dot2ScopedLaRaError;

#define asn1_type_dot2ScopedLaRaError asn1_type_dot2ScmsError

typedef enum {
  dot2LaRaPreLinkageValueResponseMsg_1_success,
  dot2LaRaPreLinkageValueResponseMsg_1_failure,
} dot2LaRaPreLinkageValueResponseMsg_1_choice;

typedef struct dot2LaRaPreLinkageValueResponseMsg_1 {
  dot2LaRaPreLinkageValueResponseMsg_1_choice choice;
  union {
    dot2PreLinkageValueRequestResponse success;
    dot2ScopedLaRaError failure;
  } u;
} dot2LaRaPreLinkageValueResponseMsg_1;

extern const ASN1CType asn1_type_dot2LaRaPreLinkageValueResponseMsg_1[];

typedef struct dot2LaRaPreLinkageValueResponseMsg {
  dot2Uint8_18 version;
  dot2HashedId8 requestHash;
  dot2LaHostnameId laId;
  dot2LaRaPreLinkageValueResponseMsg_1 reply;
} dot2LaRaPreLinkageValueResponseMsg;


extern const ASN1CType asn1_type_dot2LaRaPreLinkageValueResponseMsg[];

typedef enum {
  dot2LaRaInterfacePDU_raLaIndividualPreLinkageValueRequest,
  dot2LaRaInterfacePDU_raLaGroupPreLinkageValueRequest,
  dot2LaRaInterfacePDU_laRaPreLinkageValueResponse,
} dot2LaRaInterfacePDU_choice;

typedef struct dot2LaRaInterfacePDU {
  dot2LaRaInterfacePDU_choice choice;
  union {
    dot2RaLaIndividualPreLinkageValueRequestMsg raLaIndividualPreLinkageValueRequest;
    dot2RaLaGroupPreLinkageValueRequestMsg raLaGroupPreLinkageValueRequest;
    dot2LaRaPreLinkageValueResponseMsg laRaPreLinkageValueResponse;
  } u;
} dot2LaRaInterfacePDU;

extern const ASN1CType asn1_type_dot2LaRaInterfacePDU[];

typedef int dot2Uint8_19;

extern const ASN1CType asn1_type_dot2Uint8_19[];

typedef struct dot2ToBeSignedMaPcaPreLinkageValueRequestMsg_1 {
  dot2LinkageValue *tab;
  size_t count;
} dot2ToBeSignedMaPcaPreLinkageValueRequestMsg_1;

extern const ASN1CType asn1_type_dot2ToBeSignedMaPcaPreLinkageValueRequestMsg_1[];

typedef struct dot2ToBeSignedMaPcaPreLinkageValueRequestMsg_2 {
  dot2GroupLinkageValue *tab;
  size_t count;
} dot2ToBeSignedMaPcaPreLinkageValueRequestMsg_2;

extern const ASN1CType asn1_type_dot2ToBeSignedMaPcaPreLinkageValueRequestMsg_2[];

typedef struct dot2ToBeSignedMaPcaPreLinkageValueRequestMsg {
  dot2MaHostnameId maId;
  dot2ToBeSignedMaPcaPreLinkageValueRequestMsg_1 linkageValues;
  dot2ToBeSignedMaPcaPreLinkageValueRequestMsg_2 groupLinkageValues;
} dot2ToBeSignedMaPcaPreLinkageValueRequestMsg;


extern const ASN1CType asn1_type_dot2ToBeSignedMaPcaPreLinkageValueRequestMsg[];

typedef struct dot2MaPcaPreLinkageValueRequestMsg_1 {
  dot2Countersignature *tab;
  size_t count;
} dot2MaPcaPreLinkageValueRequestMsg_1;

extern const ASN1CType asn1_type_dot2MaPcaPreLinkageValueRequestMsg_1[];

typedef struct dot2MaPcaPreLinkageValueRequestMsg {
  dot2Uint8_19 version;
  dot2ToBeSignedMaPcaPreLinkageValueRequestMsg tbs;
  dot2MaPcaPreLinkageValueRequestMsg_1 signatures;
} dot2MaPcaPreLinkageValueRequestMsg;


extern const ASN1CType asn1_type_dot2MaPcaPreLinkageValueRequestMsg[];

typedef int dot2Uint8_20;

extern const ASN1CType asn1_type_dot2Uint8_20[];

typedef struct dot2EncryptedPlvAndHostInfo {
  dot2EncryptedIndividualPLV encryptedPLV;
  dot2Hostname hostname;
} dot2EncryptedPlvAndHostInfo;


extern const ASN1CType asn1_type_dot2EncryptedPlvAndHostInfo[];

typedef dot2ScmsError dot2ScopedMaPcaError;

#define asn1_type_dot2ScopedMaPcaError asn1_type_dot2ScmsError

typedef enum {
  dot2Lv2Plv_1_success,
  dot2Lv2Plv_1_failure,
} dot2Lv2Plv_1_choice;

typedef struct dot2Lv2Plv_1 {
  dot2Lv2Plv_1_choice choice;
  union {
    dot2EncryptedPlvAndHostInfo success;
    dot2ScopedMaPcaError failure;
  } u;
} dot2Lv2Plv_1;

extern const ASN1CType asn1_type_dot2Lv2Plv_1[];

typedef struct dot2Lv2Plv {
  dot2LinkageValue lv;
  dot2Lv2Plv_1 reply;
} dot2Lv2Plv;


extern const ASN1CType asn1_type_dot2Lv2Plv[];

typedef struct dot2PcaMaPreLinkageValueResponseMsg_1 {
  dot2Lv2Plv *tab;
  size_t count;
} dot2PcaMaPreLinkageValueResponseMsg_1;

extern const ASN1CType asn1_type_dot2PcaMaPreLinkageValueResponseMsg_1[];

typedef struct dot2PcaMaPreLinkageValueResponseMsg {
  dot2Uint8_20 version;
  dot2HashedId8 requestHash;
  dot2PcaHostnameId pcaId;
  dot2PcaMaPreLinkageValueResponseMsg_1 plvInfo;
} dot2PcaMaPreLinkageValueResponseMsg;


extern const ASN1CType asn1_type_dot2PcaMaPreLinkageValueResponseMsg[];

typedef int dot2Uint8_21;

extern const ASN1CType asn1_type_dot2Uint8_21[];

typedef struct dot2ToBeSignedMaPcaHPCRRequestMsg_1 {
  dot2LinkageValue *tab;
  size_t count;
} dot2ToBeSignedMaPcaHPCRRequestMsg_1;

extern const ASN1CType asn1_type_dot2ToBeSignedMaPcaHPCRRequestMsg_1[];

typedef struct dot2ToBeSignedMaPcaHPCRRequestMsg {
  dot2MaHostnameId maId;
  dot2ToBeSignedMaPcaHPCRRequestMsg_1 linkage_values;
} dot2ToBeSignedMaPcaHPCRRequestMsg;


extern const ASN1CType asn1_type_dot2ToBeSignedMaPcaHPCRRequestMsg[];

typedef struct dot2MaPcaHPCRRequestMsg_1 {
  dot2Countersignature *tab;
  size_t count;
} dot2MaPcaHPCRRequestMsg_1;

extern const ASN1CType asn1_type_dot2MaPcaHPCRRequestMsg_1[];

typedef struct dot2MaPcaHPCRRequestMsg {
  dot2Uint8_21 version;
  dot2ToBeSignedMaPcaHPCRRequestMsg tbs;
  dot2MaPcaHPCRRequestMsg_1 signatures;
} dot2MaPcaHPCRRequestMsg;


extern const ASN1CType asn1_type_dot2MaPcaHPCRRequestMsg[];

typedef int dot2Uint8_22;

extern const ASN1CType asn1_type_dot2Uint8_22[];

typedef dot2FullSizeHash dot2HPCR;

#define asn1_type_dot2HPCR asn1_type_dot2FullSizeHash

typedef struct dot2HPCRAndHostInfo {
  dot2HPCR hpcr;
  dot2Hostname hostname;
} dot2HPCRAndHostInfo;


extern const ASN1CType asn1_type_dot2HPCRAndHostInfo[];

typedef enum {
  dot2Lv2HPCR_1_success,
  dot2Lv2HPCR_1_failure,
} dot2Lv2HPCR_1_choice;

typedef struct dot2Lv2HPCR_1 {
  dot2Lv2HPCR_1_choice choice;
  union {
    dot2HPCRAndHostInfo success;
    dot2ScopedMaPcaError failure;
  } u;
} dot2Lv2HPCR_1;

extern const ASN1CType asn1_type_dot2Lv2HPCR_1[];

typedef struct dot2Lv2HPCR {
  dot2LinkageValue lv;
  dot2Lv2HPCR_1 reply;
} dot2Lv2HPCR;


extern const ASN1CType asn1_type_dot2Lv2HPCR[];

typedef struct dot2PcaMaHPCRResponseMsg_1 {
  dot2Lv2HPCR *tab;
  size_t count;
} dot2PcaMaHPCRResponseMsg_1;

extern const ASN1CType asn1_type_dot2PcaMaHPCRResponseMsg_1[];

typedef struct dot2PcaMaHPCRResponseMsg {
  dot2Uint8_22 version;
  dot2HashedId8 requestHash;
  dot2PcaHostnameId pcaId;
  dot2PcaMaHPCRResponseMsg_1 hpcrinfo;
} dot2PcaMaHPCRResponseMsg;


extern const ASN1CType asn1_type_dot2PcaMaHPCRResponseMsg[];

typedef enum {
  dot2MaPcaInterfacePDU_maPcaPreLinkageValueRequest,
  dot2MaPcaInterfacePDU_pcaMaPreLinkageValueResponse,
  dot2MaPcaInterfacePDU_maPcaHPCRRequest,
  dot2MaPcaInterfacePDU_pcaMaHPCRResponse,
} dot2MaPcaInterfacePDU_choice;

typedef struct dot2MaPcaInterfacePDU {
  dot2MaPcaInterfacePDU_choice choice;
  union {
    dot2MaPcaPreLinkageValueRequestMsg maPcaPreLinkageValueRequest;
    dot2PcaMaPreLinkageValueResponseMsg pcaMaPreLinkageValueResponse;
    dot2MaPcaHPCRRequestMsg maPcaHPCRRequest;
    dot2PcaMaHPCRResponseMsg pcaMaHPCRResponse;
  } u;
} dot2MaPcaInterfacePDU;

extern const ASN1CType asn1_type_dot2MaPcaInterfacePDU[];

typedef int dot2Uint8_23;

extern const ASN1CType asn1_type_dot2Uint8_23[];

typedef struct dot2ToBeSignedBlacklistingInstructionMsg_1 {
  dot2HPCR *tab;
  size_t count;
} dot2ToBeSignedBlacklistingInstructionMsg_1;

extern const ASN1CType asn1_type_dot2ToBeSignedBlacklistingInstructionMsg_1[];

typedef struct dot2ToBeSignedBlacklistingInstructionMsg {
  dot2MaHostnameId maId;
  dot2ToBeSignedBlacklistingInstructionMsg_1 hpcr;
} dot2ToBeSignedBlacklistingInstructionMsg;


extern const ASN1CType asn1_type_dot2ToBeSignedBlacklistingInstructionMsg[];

typedef struct dot2MaRaBlacklistRequestMsg_1 {
  dot2Countersignature *tab;
  size_t count;
} dot2MaRaBlacklistRequestMsg_1;

extern const ASN1CType asn1_type_dot2MaRaBlacklistRequestMsg_1[];

typedef struct dot2MaRaBlacklistRequestMsg {
  dot2Uint8_23 version;
  dot2ToBeSignedBlacklistingInstructionMsg tbs;
  dot2MaRaBlacklistRequestMsg_1 signatures;
} dot2MaRaBlacklistRequestMsg;


extern const ASN1CType asn1_type_dot2MaRaBlacklistRequestMsg[];

typedef int dot2Uint8_24;

extern const ASN1CType asn1_type_dot2Uint8_24[];

typedef dot2ScmsError dot2ScopedMaRaBlacklistError;

#define asn1_type_dot2ScopedMaRaBlacklistError asn1_type_dot2ScmsError

typedef enum {
  dot2BlacklistingStatus_1_success,
  dot2BlacklistingStatus_1_failure,
} dot2BlacklistingStatus_1_choice;

typedef struct dot2BlacklistingStatus_1 {
  dot2BlacklistingStatus_1_choice choice;
  union {
    dot2ScopedMaRaBlacklistError failure;
  } u;
} dot2BlacklistingStatus_1;

extern const ASN1CType asn1_type_dot2BlacklistingStatus_1[];

typedef struct dot2BlacklistingStatus {
  dot2HPCR hpcr;
  dot2BlacklistingStatus_1 reply;
} dot2BlacklistingStatus;


extern const ASN1CType asn1_type_dot2BlacklistingStatus[];

typedef struct dot2RaMaBlacklistResponseMsg_1 {
  dot2BlacklistingStatus *tab;
  size_t count;
} dot2RaMaBlacklistResponseMsg_1;

extern const ASN1CType asn1_type_dot2RaMaBlacklistResponseMsg_1[];

typedef struct dot2RaMaBlacklistResponseMsg {
  dot2Uint8_24 version;
  dot2HashedId8 requestHash;
  dot2RaHostnameId raId;
  dot2RaMaBlacklistResponseMsg_1 status;
} dot2RaMaBlacklistResponseMsg;


extern const ASN1CType asn1_type_dot2RaMaBlacklistResponseMsg[];

typedef int dot2Uint8_25;

extern const ASN1CType asn1_type_dot2Uint8_25[];

typedef struct dot2ToBeSignedLCIRequestMsg_1 {
  dot2HPCR *tab;
  size_t count;
} dot2ToBeSignedLCIRequestMsg_1;

extern const ASN1CType asn1_type_dot2ToBeSignedLCIRequestMsg_1[];

typedef struct dot2ToBeSignedLCIRequestMsg {
  dot2MaHostnameId maId;
  dot2ToBeSignedLCIRequestMsg_1 hpcr;
} dot2ToBeSignedLCIRequestMsg;


extern const ASN1CType asn1_type_dot2ToBeSignedLCIRequestMsg[];

typedef struct dot2MaRaLCIRequestMsg_1 {
  dot2Countersignature *tab;
  size_t count;
} dot2MaRaLCIRequestMsg_1;

extern const ASN1CType asn1_type_dot2MaRaLCIRequestMsg_1[];

typedef struct dot2MaRaLCIRequestMsg {
  dot2Uint8_25 version;
  dot2ToBeSignedLCIRequestMsg tbs;
  dot2MaRaLCIRequestMsg_1 signatures;
} dot2MaRaLCIRequestMsg;


extern const ASN1CType asn1_type_dot2MaRaLCIRequestMsg[];

typedef int dot2Uint8_26;

extern const ASN1CType asn1_type_dot2Uint8_26[];

typedef struct dot2LCIAndHostInfo {
  ASN1String iMax;
  dot2LinkageChainId la1_lci;
  dot2LinkageChainId la2_lci;
  dot2LaHostnameId la1_id;
  dot2LaHostnameId la2_id;
} dot2LCIAndHostInfo;


extern const ASN1CType asn1_type_dot2LCIAndHostInfo[];

typedef struct dot2HPCR2LCI_1 {
  ASN1String groupIdentifier;
  dot2LCIAndHostInfo info;
} dot2HPCR2LCI_1;


extern const ASN1CType asn1_type_dot2HPCR2LCI_1[];

typedef dot2ScmsError dot2ScopedMaRaLCIError;

#define asn1_type_dot2ScopedMaRaLCIError asn1_type_dot2ScmsError

typedef enum {
  dot2HPCR2LCI_2_success,
  dot2HPCR2LCI_2_failure,
} dot2HPCR2LCI_2_choice;

typedef struct dot2HPCR2LCI_2 {
  dot2HPCR2LCI_2_choice choice;
  union {
    dot2HPCR2LCI_1 success;
    dot2ScopedMaRaLCIError failure;
  } u;
} dot2HPCR2LCI_2;

extern const ASN1CType asn1_type_dot2HPCR2LCI_2[];

typedef struct dot2HPCR2LCI {
  dot2HPCR hpcr;
  dot2HPCR2LCI_2 reply;
} dot2HPCR2LCI;


extern const ASN1CType asn1_type_dot2HPCR2LCI[];

typedef struct dot2RaMaLCIResponseMsg_1 {
  dot2HPCR2LCI *tab;
  size_t count;
} dot2RaMaLCIResponseMsg_1;

extern const ASN1CType asn1_type_dot2RaMaLCIResponseMsg_1[];

typedef struct dot2RaMaLCIResponseMsg {
  dot2Uint8_26 version;
  dot2HashedId8 requestHash;
  dot2RaHostnameId raId;
  dot2RaMaLCIResponseMsg_1 lciInfo;
} dot2RaMaLCIResponseMsg;


extern const ASN1CType asn1_type_dot2RaMaLCIResponseMsg[];

typedef int dot2Uint8_27;

extern const ASN1CType asn1_type_dot2Uint8_27[];

typedef dot2HashedId8 dot2RIF;

#define asn1_type_dot2RIF asn1_type_dot2HashedId8

typedef struct dot2ToBeSignedRseObeIdBlacklistingInstructionMsg_1 {
  dot2RIF *tab;
  size_t count;
} dot2ToBeSignedRseObeIdBlacklistingInstructionMsg_1;

extern const ASN1CType asn1_type_dot2ToBeSignedRseObeIdBlacklistingInstructionMsg_1[];

typedef struct dot2ToBeSignedRseObeIdBlacklistingInstructionMsg {
  dot2MaHostnameId maId;
  dot2ToBeSignedRseObeIdBlacklistingInstructionMsg_1 rif;
} dot2ToBeSignedRseObeIdBlacklistingInstructionMsg;


extern const ASN1CType asn1_type_dot2ToBeSignedRseObeIdBlacklistingInstructionMsg[];

typedef struct dot2MaRaRseObeIdBlacklistRequestMsg_1 {
  dot2Countersignature *tab;
  size_t count;
} dot2MaRaRseObeIdBlacklistRequestMsg_1;

extern const ASN1CType asn1_type_dot2MaRaRseObeIdBlacklistRequestMsg_1[];

typedef struct dot2MaRaRseObeIdBlacklistRequestMsg {
  dot2Uint8_27 version;
  dot2ToBeSignedRseObeIdBlacklistingInstructionMsg tbs;
  dot2MaRaRseObeIdBlacklistRequestMsg_1 signatures;
} dot2MaRaRseObeIdBlacklistRequestMsg;


extern const ASN1CType asn1_type_dot2MaRaRseObeIdBlacklistRequestMsg[];

typedef int dot2Uint8_28;

extern const ASN1CType asn1_type_dot2Uint8_28[];

typedef enum {
  dot2RseObeIdBlacklistingStatus_1_success,
  dot2RseObeIdBlacklistingStatus_1_failure,
} dot2RseObeIdBlacklistingStatus_1_choice;

typedef struct dot2RseObeIdBlacklistingStatus_1 {
  dot2RseObeIdBlacklistingStatus_1_choice choice;
  union {
    dot2ScopedMaRaBlacklistError failure;
  } u;
} dot2RseObeIdBlacklistingStatus_1;

extern const ASN1CType asn1_type_dot2RseObeIdBlacklistingStatus_1[];

typedef struct dot2RseObeIdBlacklistingStatus {
  dot2RIF rif;
  dot2RseObeIdBlacklistingStatus_1 reply;
} dot2RseObeIdBlacklistingStatus;


extern const ASN1CType asn1_type_dot2RseObeIdBlacklistingStatus[];

typedef struct dot2RaMaRseObeIdBlacklistResponseMsg_1 {
  dot2RseObeIdBlacklistingStatus *tab;
  size_t count;
} dot2RaMaRseObeIdBlacklistResponseMsg_1;

extern const ASN1CType asn1_type_dot2RaMaRseObeIdBlacklistResponseMsg_1[];

typedef struct dot2RaMaRseObeIdBlacklistResponseMsg {
  dot2Uint8_28 version;
  dot2HashedId8 requestHash;
  dot2RaHostnameId raId;
  dot2RaMaRseObeIdBlacklistResponseMsg_1 status;
} dot2RaMaRseObeIdBlacklistResponseMsg;


extern const ASN1CType asn1_type_dot2RaMaRseObeIdBlacklistResponseMsg[];

typedef int dot2Uint8_29;

extern const ASN1CType asn1_type_dot2Uint8_29[];

typedef struct dot2ToBeSignedCDVRequestMsg_1 {
  dot2RIF *tab;
  size_t count;
} dot2ToBeSignedCDVRequestMsg_1;

extern const ASN1CType asn1_type_dot2ToBeSignedCDVRequestMsg_1[];

typedef struct dot2ToBeSignedCDVRequestMsg {
  dot2MaHostnameId maId;
  dot2ToBeSignedCDVRequestMsg_1 rifValues;
} dot2ToBeSignedCDVRequestMsg;


extern const ASN1CType asn1_type_dot2ToBeSignedCDVRequestMsg[];

typedef struct dot2MaRaCDVRequestMsg_1 {
  dot2Countersignature *tab;
  size_t count;
} dot2MaRaCDVRequestMsg_1;

extern const ASN1CType asn1_type_dot2MaRaCDVRequestMsg_1[];

typedef struct dot2MaRaCDVRequestMsg {
  dot2Uint8_29 version;
  dot2ToBeSignedCDVRequestMsg tbs;
  dot2MaRaCDVRequestMsg_1 signatures;
} dot2MaRaCDVRequestMsg;


extern const ASN1CType asn1_type_dot2MaRaCDVRequestMsg[];

typedef int dot2Uint8_30;

extern const ASN1CType asn1_type_dot2Uint8_30[];

typedef ASN1String dot2HashedId10;

extern const ASN1CType asn1_type_dot2HashedId10[];

typedef struct dot2CdvInfo_1 {
  dot2HashedId10 *tab;
  size_t count;
} dot2CdvInfo_1;

extern const ASN1CType asn1_type_dot2CdvInfo_1[];

typedef enum {
  dot2CdvInfo_2_success,
  dot2CdvInfo_2_failure,
} dot2CdvInfo_2_choice;

typedef struct dot2CdvInfo_2 {
  dot2CdvInfo_2_choice choice;
  union {
    dot2CdvInfo_1 success;
    dot2ScopedMaRaBlacklistError failure;
  } u;
} dot2CdvInfo_2;

extern const ASN1CType asn1_type_dot2CdvInfo_2[];

typedef struct dot2CdvInfo {
  dot2RIF rif;
  dot2CdvInfo_2 reply;
} dot2CdvInfo;


extern const ASN1CType asn1_type_dot2CdvInfo[];

typedef struct dot2RaMaCDVResponseMsg_1 {
  dot2CdvInfo *tab;
  size_t count;
} dot2RaMaCDVResponseMsg_1;

extern const ASN1CType asn1_type_dot2RaMaCDVResponseMsg_1[];

typedef struct dot2RaMaCDVResponseMsg {
  dot2Uint8_30 version;
  dot2HashedId8 requestHash;
  dot2RaHostnameId raId;
  dot2RaMaCDVResponseMsg_1 cdvInfo;
} dot2RaMaCDVResponseMsg;


extern const ASN1CType asn1_type_dot2RaMaCDVResponseMsg[];

typedef enum {
  dot2MaRaInterfacePDU_maRaBlacklistRequest,
  dot2MaRaInterfacePDU_raMaBlacklistResponse,
  dot2MaRaInterfacePDU_maRaLCIRequest,
  dot2MaRaInterfacePDU_raMaLCIResponse,
  dot2MaRaInterfacePDU_maRaRseObeIdBlacklistRequest,
  dot2MaRaInterfacePDU_raMaRseObeIdBlacklistResponse,
  dot2MaRaInterfacePDU_maRaCDVRequest,
  dot2MaRaInterfacePDU_raMaCDVResponse,
} dot2MaRaInterfacePDU_choice;

typedef struct dot2MaRaInterfacePDU {
  dot2MaRaInterfacePDU_choice choice;
  union {
    dot2MaRaBlacklistRequestMsg maRaBlacklistRequest;
    dot2RaMaBlacklistResponseMsg raMaBlacklistResponse;
    dot2MaRaLCIRequestMsg maRaLCIRequest;
    dot2RaMaLCIResponseMsg raMaLCIResponse;
    dot2MaRaRseObeIdBlacklistRequestMsg maRaRseObeIdBlacklistRequest;
    dot2RaMaRseObeIdBlacklistResponseMsg raMaRseObeIdBlacklistResponse;
    dot2MaRaCDVRequestMsg maRaCDVRequest;
    dot2RaMaCDVResponseMsg raMaCDVResponse;
  } u;
} dot2MaRaInterfacePDU;

extern const ASN1CType asn1_type_dot2MaRaInterfacePDU[];

typedef int dot2Uint8_31;

extern const ASN1CType asn1_type_dot2Uint8_31[];

typedef struct dot2PseudonymCertRequestInfo_1 {
  dot2LaHostnameId gla1_id;
  dot2LaHostnameId gla2_id;
  dot2EncryptedGroupPLV enc_gplv1;
  dot2EncryptedGroupPLV enc_gplv2;
} dot2PseudonymCertRequestInfo_1;


extern const ASN1CType asn1_type_dot2PseudonymCertRequestInfo_1[];

typedef struct dot2PseudonymCertRequestInfo {
  dot2SequenceOfPsidSsp psidSsp;
  BOOL performanceAssuranceLevel_option;
  dot2SubjectAssurance performanceAssuranceLevel;
  BOOL region_option;
  dot2GeographicRegion region;
  dot2IValue iValue;
  dot2PcaHostnameId pca_id;
  dot2EccP256CurvePoint sig_butterfly_key_B;
  dot2LaHostnameId la1_id;
  dot2LaHostnameId la2_id;
  dot2EncryptedIndividualPLV enc_plv1;
  dot2EncryptedIndividualPLV enc_plv2;
  BOOL group_linkage_info_option;
  dot2PseudonymCertRequestInfo_1 group_linkage_info;
  dot2EccP256CurvePoint enc_butterfly_key_H;
} dot2PseudonymCertRequestInfo;


extern const ASN1CType asn1_type_dot2PseudonymCertRequestInfo[];

typedef struct dot2IdCertRequestInfo {
  dot2PcaHostnameId pca_id;
  dot2CertificateType type;
  dot2ToBeSignedCertificate to_be_signed_cert;
  dot2EccP256CurvePoint response_encryption_key;
} dot2IdCertRequestInfo;


extern const ASN1CType asn1_type_dot2IdCertRequestInfo[];

typedef enum {
  dot2RaPcaCertRequestMsg_1_pseudonym_cert_req,
  dot2RaPcaCertRequestMsg_1_auth_cert_req,
} dot2RaPcaCertRequestMsg_1_choice;

typedef struct dot2RaPcaCertRequestMsg_1 {
  dot2RaPcaCertRequestMsg_1_choice choice;
  union {
    dot2PseudonymCertRequestInfo pseudonym_cert_req;
    dot2IdCertRequestInfo auth_cert_req;
  } u;
} dot2RaPcaCertRequestMsg_1;

extern const ASN1CType asn1_type_dot2RaPcaCertRequestMsg_1[];

typedef struct dot2RaPcaCertRequestMsg {
  dot2Uint8_31 version;
  dot2RaHostnameId raId;
  dot2RaPcaCertRequestMsg_1 cert_request_info;
} dot2RaPcaCertRequestMsg;


extern const ASN1CType asn1_type_dot2RaPcaCertRequestMsg[];

typedef int dot2Uint8_32;

extern const ASN1CType asn1_type_dot2Uint8_32[];

typedef dot2Ieee1609Dot2Data dot2SignedEncryptedCertificateResponse;

extern const ASN1CType asn1_type_dot2SignedEncryptedCertificateResponse[];

typedef struct dot2ImplicitCertResponse {
  dot2Certificate certificate;
  dot2EccP256PrivateKeyReconstruction priv_key_reconstruction_s;
} dot2ImplicitCertResponse;


extern const ASN1CType asn1_type_dot2ImplicitCertResponse[];

typedef struct dot2ButterflyExplicitCertResponse {
  dot2Certificate certificate;
  dot2EccP256PrivateKeyReconstruction priv_key_reconstruction_c;
} dot2ButterflyExplicitCertResponse;


extern const ASN1CType asn1_type_dot2ButterflyExplicitCertResponse[];

typedef enum {
  dot2PlaintextCertificateResponse_implicit_butterfly,
  dot2PlaintextCertificateResponse_implicit,
  dot2PlaintextCertificateResponse_explicit_butterfly,
  dot2PlaintextCertificateResponse_Explicit,
} dot2PlaintextCertificateResponse_choice;

typedef struct dot2PlaintextCertificateResponse {
  dot2PlaintextCertificateResponse_choice choice;
  union {
    dot2ImplicitCertResponse implicit_butterfly;
    dot2ImplicitCertResponse implicit;
    dot2ButterflyExplicitCertResponse explicit_butterfly;
    dot2Certificate Explicit;
  } u;
} dot2PlaintextCertificateResponse;

extern const ASN1CType asn1_type_dot2PlaintextCertificateResponse[];

typedef enum {
  dot2PcaRaCertResponseMsg_1_signed_encrypted,
  dot2PcaRaCertResponseMsg_1_raw,
} dot2PcaRaCertResponseMsg_1_choice;

typedef struct dot2PcaRaCertResponseMsg_1 {
  dot2PcaRaCertResponseMsg_1_choice choice;
  union {
    dot2SignedEncryptedCertificateResponse signed_encrypted;
    dot2PlaintextCertificateResponse raw;
  } u;
} dot2PcaRaCertResponseMsg_1;

extern const ASN1CType asn1_type_dot2PcaRaCertResponseMsg_1[];

typedef dot2ScmsError dot2ScopedPcaRaError;

#define asn1_type_dot2ScopedPcaRaError asn1_type_dot2ScmsError

typedef enum {
  dot2PcaRaCertResponseMsg_2_success,
  dot2PcaRaCertResponseMsg_2_failure,
} dot2PcaRaCertResponseMsg_2_choice;

typedef struct dot2PcaRaCertResponseMsg_2 {
  dot2PcaRaCertResponseMsg_2_choice choice;
  union {
    dot2PcaRaCertResponseMsg_1 success;
    dot2ScopedPcaRaError failure;
  } u;
} dot2PcaRaCertResponseMsg_2;

extern const ASN1CType asn1_type_dot2PcaRaCertResponseMsg_2[];

typedef struct dot2PcaRaCertResponseMsg {
  dot2Uint8_32 version;
  dot2HashedId8 requestHash;
  dot2PcaHostnameId pca_id;
  dot2PcaRaCertResponseMsg_2 reply;
} dot2PcaRaCertResponseMsg;


extern const ASN1CType asn1_type_dot2PcaRaCertResponseMsg[];

typedef enum {
  dot2PcaRaInterfacePDU_raPcaCertRequest,
  dot2PcaRaInterfacePDU_pcaRaCertResponse,
} dot2PcaRaInterfacePDU_choice;

typedef struct dot2PcaRaInterfacePDU {
  dot2PcaRaInterfacePDU_choice choice;
  union {
    dot2RaPcaCertRequestMsg raPcaCertRequest;
    dot2PcaRaCertResponseMsg pcaRaCertResponse;
  } u;
} dot2PcaRaInterfacePDU;

extern const ASN1CType asn1_type_dot2PcaRaInterfacePDU[];

typedef dot2Ieee1609Dot2Data dot2EncryptedCertificateData;

extern const ASN1CType asn1_type_dot2EncryptedCertificateData[];

typedef struct dot2ToBeSignedEncryptedCertificateResponse {
  dot2SequenceOfPsidSsp psidSsp;
  dot2Time32 expiration;
  dot2Duration lifetime;
  dot2EncryptedCertificateData encrypted_cert;
} dot2ToBeSignedEncryptedCertificateResponse;


extern const ASN1CType asn1_type_dot2ToBeSignedEncryptedCertificateResponse[];

typedef dot2Ieee1609Dot2Data dot2DecryptedCertificateData;

#define asn1_type_dot2DecryptedCertificateData asn1_type_dot2Ieee1609Dot2Data

typedef enum dot2RaPgError {
  dot2RaPgError_raPgMalformedRequest,
  dot2RaPgError_raPgSignatureFailed,
  dot2RaPgError_raPgPolicyError,
} dot2RaPgError;

extern const ASN1CType asn1_type_dot2RaPgError[];

typedef int dot2Uint8_33;

extern const ASN1CType asn1_type_dot2Uint8_33[];

typedef dot2Uint8 dot2ScmsVersion;

#define asn1_type_dot2ScmsVersion asn1_type_dot2Uint8

typedef struct dot2GlobalPolicyData_1 {
  dot2Time64 startTime;
  dot2ScmsVersion scmsVersion;
} dot2GlobalPolicyData_1;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_1[];

typedef struct dot2GlobalPolicyData_2 {
  dot2GlobalPolicyData_1 *tab;
  size_t count;
} dot2GlobalPolicyData_2;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_2[];

typedef struct dot2GlobalPolicyData_3 {
  dot2ScmsVersion initialScmsVersion;
  dot2GlobalPolicyData_2 intervals;
} dot2GlobalPolicyData_3;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_3[];

typedef dot2Uint16 dot2GlobalCertChainFileID;

#define asn1_type_dot2GlobalCertChainFileID asn1_type_dot2Uint16

typedef struct dot2GlobalPolicyData_4 {
  dot2Time64 startTime;
  dot2GlobalCertChainFileID globalCertChainFileID;
} dot2GlobalPolicyData_4;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_4[];

typedef struct dot2GlobalPolicyData_5 {
  dot2GlobalPolicyData_4 *tab;
  size_t count;
} dot2GlobalPolicyData_5;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_5[];

typedef struct dot2GlobalPolicyData_6 {
  dot2GlobalCertChainFileID initialGlobalCertChainFileID;
  dot2GlobalPolicyData_5 intervals;
} dot2GlobalPolicyData_6;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_6[];

typedef dot2Duration dot2OverdueCrlTolerance;

#define asn1_type_dot2OverdueCrlTolerance asn1_type_dot2Duration

typedef struct dot2GlobalPolicyData_7 {
  dot2Time64 startTime;
  dot2OverdueCrlTolerance overdueCrlTolerance;
} dot2GlobalPolicyData_7;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_7[];

typedef struct dot2GlobalPolicyData_8 {
  dot2GlobalPolicyData_7 *tab;
  size_t count;
} dot2GlobalPolicyData_8;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_8[];

typedef struct dot2GlobalPolicyData_9 {
  dot2OverdueCrlTolerance initialOverdueCrlTolerance;
  dot2GlobalPolicyData_8 intervals;
} dot2GlobalPolicyData_9;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_9[];

typedef dot2Duration dot2IPeriod;

#define asn1_type_dot2IPeriod asn1_type_dot2Duration

typedef struct dot2GlobalPolicyData_10 {
  dot2Time64 startTime;
  dot2IPeriod iPeriod;
} dot2GlobalPolicyData_10;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_10[];

typedef struct dot2GlobalPolicyData_11 {
  dot2GlobalPolicyData_10 *tab;
  size_t count;
} dot2GlobalPolicyData_11;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_11[];

typedef struct dot2GlobalPolicyData_12 {
  dot2IPeriod initialIPeriod;
  dot2GlobalPolicyData_11 intervals;
} dot2GlobalPolicyData_12;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_12[];

typedef dot2Uint8 dot2MinCertsPerIPeriod;

#define asn1_type_dot2MinCertsPerIPeriod asn1_type_dot2Uint8

typedef struct dot2GlobalPolicyData_13 {
  dot2Time64 startTime;
  dot2MinCertsPerIPeriod minCertsPerIPeriod;
} dot2GlobalPolicyData_13;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_13[];

typedef struct dot2GlobalPolicyData_14 {
  dot2GlobalPolicyData_13 *tab;
  size_t count;
} dot2GlobalPolicyData_14;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_14[];

typedef struct dot2GlobalPolicyData_15 {
  dot2MinCertsPerIPeriod initialMinCertsPerIPeriod;
  dot2GlobalPolicyData_14 intervals;
} dot2GlobalPolicyData_15;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_15[];

typedef enum dot2CertValidityModel {
  dot2CertValidityModel_concurrent,
  dot2CertValidityModel_non_concurrent,
} dot2CertValidityModel;

extern const ASN1CType asn1_type_dot2CertValidityModel[];

typedef struct dot2GlobalPolicyData_16 {
  dot2Time64 startTime;
  dot2CertValidityModel certValidityModel;
} dot2GlobalPolicyData_16;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_16[];

typedef struct dot2GlobalPolicyData_17 {
  dot2GlobalPolicyData_16 *tab;
  size_t count;
} dot2GlobalPolicyData_17;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_17[];

typedef struct dot2GlobalPolicyData_18 {
  dot2CertValidityModel initialCertValidityModel;
  dot2GlobalPolicyData_17 intervals;
} dot2GlobalPolicyData_18;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_18[];

typedef dot2Duration dot2MaxAvailableCertSupply;

#define asn1_type_dot2MaxAvailableCertSupply asn1_type_dot2Duration

typedef struct dot2GlobalPolicyData_19 {
  dot2Time64 startTime;
  dot2MaxAvailableCertSupply maxAvailableCertSupply;
} dot2GlobalPolicyData_19;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_19[];

typedef struct dot2GlobalPolicyData_20 {
  dot2GlobalPolicyData_19 *tab;
  size_t count;
} dot2GlobalPolicyData_20;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_20[];

typedef struct dot2GlobalPolicyData_21 {
  dot2MaxAvailableCertSupply initialMaxAvailableCertSupply;
  dot2GlobalPolicyData_20 intervals;
} dot2GlobalPolicyData_21;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_21[];

typedef dot2Duration dot2MaxCertRequestAge;

#define asn1_type_dot2MaxCertRequestAge asn1_type_dot2Duration

typedef struct dot2GlobalPolicyData_22 {
  dot2Time64 startTime;
  dot2MaxCertRequestAge maxCertRequestAge;
} dot2GlobalPolicyData_22;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_22[];

typedef struct dot2GlobalPolicyData_23 {
  dot2GlobalPolicyData_22 *tab;
  size_t count;
} dot2GlobalPolicyData_23;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_23[];

typedef struct dot2GlobalPolicyData_24 {
  dot2MaxCertRequestAge initialMaxCertRequestAge;
  dot2GlobalPolicyData_23 intervals;
} dot2GlobalPolicyData_24;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_24[];

typedef dot2Uint32 dot2ShuffleThreshold;

#define asn1_type_dot2ShuffleThreshold asn1_type_dot2Uint32

typedef struct dot2GlobalPolicyData_25 {
  dot2Time64 startTime;
  dot2ShuffleThreshold shuffleThreshold;
} dot2GlobalPolicyData_25;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_25[];

typedef struct dot2GlobalPolicyData_26 {
  dot2GlobalPolicyData_25 *tab;
  size_t count;
} dot2GlobalPolicyData_26;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_26[];

typedef struct dot2GlobalPolicyData_27 {
  dot2ShuffleThreshold initialShuffleThreshold;
  dot2GlobalPolicyData_26 intervals;
} dot2GlobalPolicyData_27;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_27[];

typedef dot2Uint8 dot2HashOfRequestSize;

#define asn1_type_dot2HashOfRequestSize asn1_type_dot2Uint8

typedef struct dot2GlobalPolicyData_28 {
  dot2Time64 startTime;
  dot2HashOfRequestSize hashOfRequestSize;
} dot2GlobalPolicyData_28;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_28[];

typedef struct dot2GlobalPolicyData_29 {
  dot2GlobalPolicyData_28 *tab;
  size_t count;
} dot2GlobalPolicyData_29;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_29[];

typedef struct dot2GlobalPolicyData_30 {
  dot2HashOfRequestSize initialHashOfRequestSize;
  dot2GlobalPolicyData_29 intervals;
} dot2GlobalPolicyData_30;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_30[];

typedef dot2Duration dot2MaxGpfGccfRetrievalInterval;

#define asn1_type_dot2MaxGpfGccfRetrievalInterval asn1_type_dot2Duration

typedef struct dot2GlobalPolicyData_31 {
  dot2Time64 startTime;
  dot2MaxGpfGccfRetrievalInterval maxGpfGccfRetrievalInterval;
} dot2GlobalPolicyData_31;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_31[];

typedef struct dot2GlobalPolicyData_32 {
  dot2GlobalPolicyData_31 *tab;
  size_t count;
} dot2GlobalPolicyData_32;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_32[];

typedef struct dot2GlobalPolicyData_33 {
  dot2MaxGpfGccfRetrievalInterval initialMaxGpfGccfRetrievalInterval;
  dot2GlobalPolicyData_32 intervals;
} dot2GlobalPolicyData_33;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_33[];

typedef dot2Duration dot2RseApplicationCertValidity;

#define asn1_type_dot2RseApplicationCertValidity asn1_type_dot2Duration

typedef struct dot2GlobalPolicyData_34 {
  dot2Time64 startTime;
  dot2RseApplicationCertValidity rseApplicationCertValidity;
} dot2GlobalPolicyData_34;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_34[];

typedef struct dot2GlobalPolicyData_35 {
  dot2GlobalPolicyData_34 *tab;
  size_t count;
} dot2GlobalPolicyData_35;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_35[];

typedef struct dot2GlobalPolicyData_36 {
  dot2RseApplicationCertValidity initialRseApplicationCertValidity;
  dot2GlobalPolicyData_35 intervals;
} dot2GlobalPolicyData_36;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_36[];

typedef dot2Duration dot2RseApplicationCertOverlap;

#define asn1_type_dot2RseApplicationCertOverlap asn1_type_dot2Duration

typedef struct dot2GlobalPolicyData_37 {
  dot2Time64 startTime;
  dot2RseApplicationCertOverlap rseApplicationCertOverlap;
} dot2GlobalPolicyData_37;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_37[];

typedef struct dot2GlobalPolicyData_38 {
  dot2GlobalPolicyData_37 *tab;
  size_t count;
} dot2GlobalPolicyData_38;

extern const ASN1CType asn1_type_dot2GlobalPolicyData_38[];

typedef struct dot2GlobalPolicyData_39 {
  dot2RseApplicationCertOverlap initialRseApplicationCertOverlap;
  dot2GlobalPolicyData_38 intervals;
} dot2GlobalPolicyData_39;


extern const ASN1CType asn1_type_dot2GlobalPolicyData_39[];

typedef struct dot2GlobalPolicyData {
  BOOL temporalSeriesOfScmsVersion_option;
  dot2GlobalPolicyData_3 temporalSeriesOfScmsVersion;
  BOOL temporalSeriesOfCertChainFileID_option;
  dot2GlobalPolicyData_6 temporalSeriesOfCertChainFileID;
  BOOL temporalSeriesOfOverdueCrlTolerance_option;
  dot2GlobalPolicyData_9 temporalSeriesOfOverdueCrlTolerance;
  BOOL temporalSeriesOfIPeriod_option;
  dot2GlobalPolicyData_12 temporalSeriesOfIPeriod;
  BOOL temporalSeriesOfMinCertsPerIPeriod_option;
  dot2GlobalPolicyData_15 temporalSeriesOfMinCertsPerIPeriod;
  BOOL temporalSeriesOfCertValidityModel_option;
  dot2GlobalPolicyData_18 temporalSeriesOfCertValidityModel;
  BOOL temporalSeriesOfMaxAvailableCertSupply_option;
  dot2GlobalPolicyData_21 temporalSeriesOfMaxAvailableCertSupply;
  BOOL temporalSeriesOfMaxCertRequestAge_option;
  dot2GlobalPolicyData_24 temporalSeriesOfMaxCertRequestAge;
  BOOL temporalSeriesOfShuffleThreshold_option;
  dot2GlobalPolicyData_27 temporalSeriesOfShuffleThreshold;
  BOOL temporalSeriesOfHashOfRequestSize_option;
  dot2GlobalPolicyData_30 temporalSeriesOfHashOfRequestSize;
  BOOL temporalSeriesOfMaxGpfGccfRetrievalInterval_option;
  dot2GlobalPolicyData_33 temporalSeriesOfMaxGpfGccfRetrievalInterval;
  BOOL temporalSeriesOfRseApplicationCertValidity_option;
  dot2GlobalPolicyData_36 temporalSeriesOfRseApplicationCertValidity;
  BOOL temporalSeriesOfRseApplicationCertOVerlap_option;
  dot2GlobalPolicyData_39 temporalSeriesOfRseApplicationCertOVerlap;
} dot2GlobalPolicyData;


extern const ASN1CType asn1_type_dot2GlobalPolicyData[];

typedef struct dot2CustomPolicyData {
  BOOL requestingRaHostname_option;
  dot2RaHostnameId requestingRaHostname;
  dot2GlobalPolicyData globalPolicy;
} dot2CustomPolicyData;


extern const ASN1CType asn1_type_dot2CustomPolicyData[];

typedef struct dot2LocalPolicyData_1 {
  dot2Time64 startTime;
  dot2ShuffleThreshold shuffleThreshold;
} dot2LocalPolicyData_1;


extern const ASN1CType asn1_type_dot2LocalPolicyData_1[];

typedef struct dot2LocalPolicyData_2 {
  dot2LocalPolicyData_1 *tab;
  size_t count;
} dot2LocalPolicyData_2;

extern const ASN1CType asn1_type_dot2LocalPolicyData_2[];

typedef struct dot2LocalPolicyData_3 {
  dot2ShuffleThreshold initialShuffleThreshold;
  dot2LocalPolicyData_2 intervals;
} dot2LocalPolicyData_3;


extern const ASN1CType asn1_type_dot2LocalPolicyData_3[];

typedef dot2Uint8 dot2CertsPerIPeriod;

#define asn1_type_dot2CertsPerIPeriod asn1_type_dot2Uint8

typedef struct dot2LocalPolicyData_4 {
  dot2Time64 startTime;
  dot2CertsPerIPeriod certsPerIPeriod;
} dot2LocalPolicyData_4;


extern const ASN1CType asn1_type_dot2LocalPolicyData_4[];

typedef struct dot2LocalPolicyData_5 {
  dot2LocalPolicyData_4 *tab;
  size_t count;
} dot2LocalPolicyData_5;

extern const ASN1CType asn1_type_dot2LocalPolicyData_5[];

typedef struct dot2LocalPolicyData_6 {
  dot2CertsPerIPeriod initialCertsPerIPeriod;
  dot2LocalPolicyData_5 intervals;
} dot2LocalPolicyData_6;


extern const ASN1CType asn1_type_dot2LocalPolicyData_6[];

typedef struct dot2LocalPolicyData_7 {
  dot2Time64 startTime;
  dot2LaHostnameId laOneHost;
} dot2LocalPolicyData_7;


extern const ASN1CType asn1_type_dot2LocalPolicyData_7[];

typedef struct dot2LocalPolicyData_8 {
  dot2LocalPolicyData_7 *tab;
  size_t count;
} dot2LocalPolicyData_8;

extern const ASN1CType asn1_type_dot2LocalPolicyData_8[];

typedef struct dot2LocalPolicyData_9 {
  dot2LaHostnameId initialLaOneHost;
  dot2LocalPolicyData_8 intervals;
} dot2LocalPolicyData_9;


extern const ASN1CType asn1_type_dot2LocalPolicyData_9[];

typedef struct dot2LocalPolicyData_10 {
  dot2Time64 startTime;
  dot2LaHostnameId laTwoHost;
} dot2LocalPolicyData_10;


extern const ASN1CType asn1_type_dot2LocalPolicyData_10[];

typedef struct dot2LocalPolicyData_11 {
  dot2LocalPolicyData_10 *tab;
  size_t count;
} dot2LocalPolicyData_11;

extern const ASN1CType asn1_type_dot2LocalPolicyData_11[];

typedef struct dot2LocalPolicyData_12 {
  dot2LaHostnameId initialLaTwoHost;
  dot2LocalPolicyData_11 intervals;
} dot2LocalPolicyData_12;


extern const ASN1CType asn1_type_dot2LocalPolicyData_12[];

typedef struct dot2LocalPolicyData_13 {
  dot2Time64 startTime;
  dot2PcaHostnameId pcaHost;
} dot2LocalPolicyData_13;


extern const ASN1CType asn1_type_dot2LocalPolicyData_13[];

typedef struct dot2LocalPolicyData_14 {
  dot2LocalPolicyData_13 *tab;
  size_t count;
} dot2LocalPolicyData_14;

extern const ASN1CType asn1_type_dot2LocalPolicyData_14[];

typedef struct dot2LocalPolicyData_15 {
  dot2PcaHostnameId initialPcaHost;
  dot2LocalPolicyData_14 intervals;
} dot2LocalPolicyData_15;


extern const ASN1CType asn1_type_dot2LocalPolicyData_15[];

typedef dot2Opaque dot2X509TlsCert;

#define asn1_type_dot2X509TlsCert asn1_type_dot2Opaque

typedef struct dot2LocalPolicyData_16 {
  dot2Time64 startTime;
  dot2X509TlsCert raX509TlsCert;
} dot2LocalPolicyData_16;


extern const ASN1CType asn1_type_dot2LocalPolicyData_16[];

typedef struct dot2LocalPolicyData_17 {
  dot2LocalPolicyData_16 *tab;
  size_t count;
} dot2LocalPolicyData_17;

extern const ASN1CType asn1_type_dot2LocalPolicyData_17[];

typedef struct dot2LocalPolicyData_18 {
  dot2X509TlsCert initialRaX509TlsCert;
  dot2LocalPolicyData_17 intervals;
} dot2LocalPolicyData_18;


extern const ASN1CType asn1_type_dot2LocalPolicyData_18[];

typedef struct dot2LocalPolicyData_19 {
  dot2Time64 startTime;
  dot2X509TlsCert laX509TlsCert;
} dot2LocalPolicyData_19;


extern const ASN1CType asn1_type_dot2LocalPolicyData_19[];

typedef struct dot2LocalPolicyData_20 {
  dot2LocalPolicyData_19 *tab;
  size_t count;
} dot2LocalPolicyData_20;

extern const ASN1CType asn1_type_dot2LocalPolicyData_20[];

typedef struct dot2LocalPolicyData_21 {
  dot2X509TlsCert initialLaX509TlsCert;
  dot2LocalPolicyData_20 intervals;
} dot2LocalPolicyData_21;


extern const ASN1CType asn1_type_dot2LocalPolicyData_21[];

typedef struct dot2LocalPolicyData_22 {
  dot2Time64 startTime;
  dot2X509TlsCert pcaX509TlsCert;
} dot2LocalPolicyData_22;


extern const ASN1CType asn1_type_dot2LocalPolicyData_22[];

typedef struct dot2LocalPolicyData_23 {
  dot2LocalPolicyData_22 *tab;
  size_t count;
} dot2LocalPolicyData_23;

extern const ASN1CType asn1_type_dot2LocalPolicyData_23[];

typedef struct dot2LocalPolicyData_24 {
  dot2X509TlsCert initialPcaX509TlsCert;
  dot2LocalPolicyData_23 intervals;
} dot2LocalPolicyData_24;


extern const ASN1CType asn1_type_dot2LocalPolicyData_24[];

typedef dot2Duration dot2SharedKeyUpdateInterval;

#define asn1_type_dot2SharedKeyUpdateInterval asn1_type_dot2Duration

typedef struct dot2LocalPolicyData_25 {
  dot2Time64 startTime;
  dot2SharedKeyUpdateInterval sharedKeyUpdateInterval;
} dot2LocalPolicyData_25;


extern const ASN1CType asn1_type_dot2LocalPolicyData_25[];

typedef struct dot2LocalPolicyData_26 {
  dot2LocalPolicyData_25 *tab;
  size_t count;
} dot2LocalPolicyData_26;

extern const ASN1CType asn1_type_dot2LocalPolicyData_26[];

typedef struct dot2LocalPolicyData_27 {
  dot2SharedKeyUpdateInterval initialSharedKeyUpdateInterval;
  dot2LocalPolicyData_26 intervals;
} dot2LocalPolicyData_27;


extern const ASN1CType asn1_type_dot2LocalPolicyData_27[];

typedef struct dot2LocalPolicyData {
  BOOL temporalSeriesOfShuffleThreshold_option;
  dot2LocalPolicyData_3 temporalSeriesOfShuffleThreshold;
  BOOL temporalSeriesOfCertsPerIPeriod_option;
  dot2LocalPolicyData_6 temporalSeriesOfCertsPerIPeriod;
  BOOL temporalSeriesOfLaOneHost_option;
  dot2LocalPolicyData_9 temporalSeriesOfLaOneHost;
  BOOL temporalSeriesOfLaTwoHost_option;
  dot2LocalPolicyData_12 temporalSeriesOfLaTwoHost;
  BOOL temporalSeriesOfPcaHost_option;
  dot2LocalPolicyData_15 temporalSeriesOfPcaHost;
  BOOL temporalSeriesOfRaX509TlsCert_option;
  dot2LocalPolicyData_18 temporalSeriesOfRaX509TlsCert;
  BOOL temporalSeriesOfLaX509TlsCert_option;
  dot2LocalPolicyData_21 temporalSeriesOfLaX509TlsCert;
  BOOL temporalSeriesOfPcaX509TlsCert_option;
  dot2LocalPolicyData_24 temporalSeriesOfPcaX509TlsCert;
  BOOL temporalSeriesOfSharedKeyUpdateInterval_option;
  dot2LocalPolicyData_27 temporalSeriesOfSharedKeyUpdateInterval;
} dot2LocalPolicyData;


extern const ASN1CType asn1_type_dot2LocalPolicyData[];

typedef enum {
  dot2Policy_global,
  dot2Policy_custom,
  dot2Policy_local,
} dot2Policy_choice;

typedef struct dot2Policy {
  dot2Policy_choice choice;
  union {
    dot2GlobalPolicyData global;
    dot2CustomPolicyData custom;
    dot2LocalPolicyData local;
  } u;
} dot2Policy;

extern const ASN1CType asn1_type_dot2Policy[];

typedef struct dot2ToBeSignedPolicyData {
  ASN1String policyID;
  dot2Time64 generationTime;
  dot2Time64 activeTime;
  dot2Policy policy;
} dot2ToBeSignedPolicyData;


extern const ASN1CType asn1_type_dot2ToBeSignedPolicyData[];

typedef dot2ToBeSignedPolicyData dot2ToBeSignedCustomPolicyFile;

extern const ASN1CType asn1_type_dot2ToBeSignedCustomPolicyFile[];

typedef struct dot2RaPgPolicySignatureRequestMsg {
  dot2Uint8_33 version;
  dot2ToBeSignedCustomPolicyFile tbs;
} dot2RaPgPolicySignatureRequestMsg;


extern const ASN1CType asn1_type_dot2RaPgPolicySignatureRequestMsg[];

typedef int dot2Uint8_34;

extern const ASN1CType asn1_type_dot2Uint8_34[];

typedef int dot2Uint8_37;

extern const ASN1CType asn1_type_dot2Uint8_37[];

typedef struct dot2BasePolicyFile_1 {
  dot2Countersignature *tab;
  size_t count;
} dot2BasePolicyFile_1;

extern const ASN1CType asn1_type_dot2BasePolicyFile_1[];

typedef struct dot2BasePolicyFile {
  dot2Uint8_37 version;
  dot2ToBeSignedPolicyData tbsData;
  dot2BasePolicyFile_1 signatures;
} dot2BasePolicyFile;


extern const ASN1CType asn1_type_dot2BasePolicyFile[];

typedef dot2BasePolicyFile dot2SignedCustomPolicyFile;

extern const ASN1CType asn1_type_dot2SignedCustomPolicyFile[];

typedef enum {
  dot2RaPgPolicySignatureRequestReplyMsg_1_success,
  dot2RaPgPolicySignatureRequestReplyMsg_1_failure,
} dot2RaPgPolicySignatureRequestReplyMsg_1_choice;

typedef struct dot2RaPgPolicySignatureRequestReplyMsg_1 {
  dot2RaPgPolicySignatureRequestReplyMsg_1_choice choice;
  union {
    dot2SignedCustomPolicyFile success;
    dot2RaPgError failure;
  } u;
} dot2RaPgPolicySignatureRequestReplyMsg_1;

extern const ASN1CType asn1_type_dot2RaPgPolicySignatureRequestReplyMsg_1[];

typedef struct dot2RaPgPolicySignatureRequestReplyMsg {
  dot2Uint8_34 version;
  dot2RaPgPolicySignatureRequestReplyMsg_1 signedFile;
} dot2RaPgPolicySignatureRequestReplyMsg;


extern const ASN1CType asn1_type_dot2RaPgPolicySignatureRequestReplyMsg[];

typedef enum {
  dot2RaPgInterfacePDU_raPgPolicySignatureRequest,
  dot2RaPgInterfacePDU_raPgPolicySignatureRequestReply,
} dot2RaPgInterfacePDU_choice;

typedef struct dot2RaPgInterfacePDU {
  dot2RaPgInterfacePDU_choice choice;
  union {
    dot2RaPgPolicySignatureRequestMsg raPgPolicySignatureRequest;
    dot2RaPgPolicySignatureRequestReplyMsg raPgPolicySignatureRequestReply;
  } u;
} dot2RaPgInterfacePDU;

extern const ASN1CType asn1_type_dot2RaPgInterfacePDU[];

typedef int dot2CountryOnly_1;

extern const ASN1CType asn1_type_dot2CountryOnly_1[];

typedef dot2CountryOnly_1 dot2Canada;

#define asn1_type_dot2Canada asn1_type_dot2CountryOnly_1

typedef int dot2CountryOnly_2;

extern const ASN1CType asn1_type_dot2CountryOnly_2[];

typedef dot2CountryOnly_2 dot2Mexico;

#define asn1_type_dot2Mexico asn1_type_dot2CountryOnly_2

typedef int dot2CountryOnly_3;

extern const ASN1CType asn1_type_dot2CountryOnly_3[];

typedef dot2CountryOnly_3 dot2USA;

#define asn1_type_dot2USA asn1_type_dot2CountryOnly_3

typedef dot2Duration dot2CrlgCertExpiration;

#define asn1_type_dot2CrlgCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2DcmCertExpiration;

#define asn1_type_dot2DcmCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2EcaCertExpirationCvp;

#define asn1_type_dot2EcaCertExpirationCvp asn1_type_dot2Duration

typedef dot2Duration dot2EcaCertExpirationPoc;

#define asn1_type_dot2EcaCertExpirationPoc asn1_type_dot2Duration

typedef dot2Duration dot2ElectorCertExpiration;

#define asn1_type_dot2ElectorCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2IcaCertExpirationCvp;

#define asn1_type_dot2IcaCertExpirationCvp asn1_type_dot2Duration

typedef dot2Duration dot2IcaCertExpirationPoc;

#define asn1_type_dot2IcaCertExpirationPoc asn1_type_dot2Duration

typedef dot2Duration dot2LaCertExpiration;

#define asn1_type_dot2LaCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2MaCertExpiration;

#define asn1_type_dot2MaCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2PcaCertExpiration;

#define asn1_type_dot2PcaCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2PgCertExpiration;

#define asn1_type_dot2PgCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2ObeEnrollmentCertExpirationCvp;

#define asn1_type_dot2ObeEnrollmentCertExpirationCvp asn1_type_dot2Duration

typedef dot2Duration dot2ObeEnrollmentCertExpirationPoc;

#define asn1_type_dot2ObeEnrollmentCertExpirationPoc asn1_type_dot2Duration

typedef dot2Duration dot2ObeIdentificationCertExpiration;

#define asn1_type_dot2ObeIdentificationCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2ObePseudonymCertExpiration;

#define asn1_type_dot2ObePseudonymCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2RaCertExpiration;

#define asn1_type_dot2RaCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2RseApplicationCertExpiration;

#define asn1_type_dot2RseApplicationCertExpiration asn1_type_dot2Duration

typedef dot2Duration dot2RseEnrollmentCertExpirationCvp;

#define asn1_type_dot2RseEnrollmentCertExpirationCvp asn1_type_dot2Duration

typedef dot2Duration dot2RseEnrollmentCertExpirationPoc;

#define asn1_type_dot2RseEnrollmentCertExpirationPoc asn1_type_dot2Duration

typedef dot2Duration dot2RootCaCertExpiration;

#define asn1_type_dot2RootCaCertExpiration asn1_type_dot2Duration

typedef int dot2Psid_1;

extern const ASN1CType asn1_type_dot2Psid_1[];

typedef dot2Psid_1 dot2BsmPsid;

#define asn1_type_dot2BsmPsid asn1_type_dot2Psid_1

typedef int dot2Psid_2;

extern const ASN1CType asn1_type_dot2Psid_2[];

typedef dot2Psid_2 dot2SecurityMgmtPsid;

#define asn1_type_dot2SecurityMgmtPsid asn1_type_dot2Psid_2

typedef int dot2Psid_3;

extern const ASN1CType asn1_type_dot2Psid_3[];

typedef dot2Psid_3 dot2MisbehaviorReportingPsid;

#define asn1_type_dot2MisbehaviorReportingPsid asn1_type_dot2Psid_3

typedef int dot2Psid_4;

extern const ASN1CType asn1_type_dot2Psid_4[];

typedef dot2Psid_4 dot2VulnerableRoadUsersSafetyPsid;

#define asn1_type_dot2VulnerableRoadUsersSafetyPsid asn1_type_dot2Psid_4

typedef int dot2Psid_5;

extern const ASN1CType asn1_type_dot2Psid_5[];

typedef dot2Psid_5 dot2DifferentialGpsCorrectionsUncompressedPsid;

#define asn1_type_dot2DifferentialGpsCorrectionsUncompressedPsid asn1_type_dot2Psid_5

typedef int dot2Psid_6;

extern const ASN1CType asn1_type_dot2Psid_6[];

typedef dot2Psid_6 dot2DifferentialGpsCorrectionsCompressedPsid;

#define asn1_type_dot2DifferentialGpsCorrectionsCompressedPsid asn1_type_dot2Psid_6

typedef int dot2Psid_7;

extern const ASN1CType asn1_type_dot2Psid_7[];

typedef dot2Psid_7 dot2IntersectionSafetyAndAwarenessPsid;

#define asn1_type_dot2IntersectionSafetyAndAwarenessPsid asn1_type_dot2Psid_7

typedef int dot2Psid_8;

extern const ASN1CType asn1_type_dot2Psid_8[];

typedef dot2Psid_8 dot2TravellerInformationAndRoadsideSignagePsid;

#define asn1_type_dot2TravellerInformationAndRoadsideSignagePsid asn1_type_dot2Psid_8

typedef int dot2Psid_9;

extern const ASN1CType asn1_type_dot2Psid_9[];

typedef dot2Psid_9 dot2WaveServiceAdvertisementPsid;

#define asn1_type_dot2WaveServiceAdvertisementPsid asn1_type_dot2Psid_9

typedef int dot2Psid_10;

extern const ASN1CType asn1_type_dot2Psid_10[];

typedef dot2Psid_10 dot2VehicleInitiatedDistressNotificationPsid;

#define asn1_type_dot2VehicleInitiatedDistressNotificationPsid asn1_type_dot2Psid_10

typedef int dot2Psid_11;

extern const ASN1CType asn1_type_dot2Psid_11[];

typedef dot2Psid_11 dot2TranscoreSoftwareUpdatePsid;

#define asn1_type_dot2TranscoreSoftwareUpdatePsid asn1_type_dot2Psid_11

typedef int dot2Psid_12;

extern const ASN1CType asn1_type_dot2Psid_12[];

typedef dot2Psid_12 dot2CVPApplication1Psid;

#define asn1_type_dot2CVPApplication1Psid asn1_type_dot2Psid_12

typedef int dot2Psid_13;

extern const ASN1CType asn1_type_dot2Psid_13[];

typedef dot2Psid_13 dot2CVPApplication2Psid;

#define asn1_type_dot2CVPApplication2Psid asn1_type_dot2Psid_13

typedef int dot2Psid_14;

extern const ASN1CType asn1_type_dot2Psid_14[];

typedef dot2Psid_14 dot2CVPApplication3Psid;

#define asn1_type_dot2CVPApplication3Psid asn1_type_dot2Psid_14

typedef int dot2Psid_15;

extern const ASN1CType asn1_type_dot2Psid_15[];

typedef dot2Psid_15 dot2CVPApplication4Psid;

#define asn1_type_dot2CVPApplication4Psid asn1_type_dot2Psid_15

typedef int dot2Psid_16;

extern const ASN1CType asn1_type_dot2Psid_16[];

typedef dot2Psid_16 dot2CVPApplication5Psid;

#define asn1_type_dot2CVPApplication5Psid asn1_type_dot2Psid_16

typedef int dot2Psid_17;

extern const ASN1CType asn1_type_dot2Psid_17[];

typedef dot2Psid_17 dot2CVPApplication6Psid;

#define asn1_type_dot2CVPApplication6Psid asn1_type_dot2Psid_17

typedef int dot2Psid_18;

extern const ASN1CType asn1_type_dot2Psid_18[];

typedef dot2Psid_18 dot2CVPApplication7Psid;

#define asn1_type_dot2CVPApplication7Psid asn1_type_dot2Psid_18

typedef int dot2Psid_19;

extern const ASN1CType asn1_type_dot2Psid_19[];

typedef dot2Psid_19 dot2CVPApplication8Psid;

#define asn1_type_dot2CVPApplication8Psid asn1_type_dot2Psid_19

typedef int dot2Psid_20;

extern const ASN1CType asn1_type_dot2Psid_20[];

typedef dot2Psid_20 dot2CVPApplication9Psid;

#define asn1_type_dot2CVPApplication9Psid asn1_type_dot2Psid_20

typedef int dot2Psid_21;

extern const ASN1CType asn1_type_dot2Psid_21[];

typedef dot2Psid_21 dot2CVPApplication10Psid;

#define asn1_type_dot2CVPApplication10Psid asn1_type_dot2Psid_21

typedef int dot2Psid_22;

extern const ASN1CType asn1_type_dot2Psid_22[];

typedef dot2Psid_22 dot2CVPApplication11Psid;

#define asn1_type_dot2CVPApplication11Psid asn1_type_dot2Psid_22

typedef int dot2Psid_23;

extern const ASN1CType asn1_type_dot2Psid_23[];

typedef dot2Psid_23 dot2CVPApplication12Psid;

#define asn1_type_dot2CVPApplication12Psid asn1_type_dot2Psid_23

typedef int dot2Psid_24;

extern const ASN1CType asn1_type_dot2Psid_24[];

typedef dot2Psid_24 dot2CVPApplication13Psid;

#define asn1_type_dot2CVPApplication13Psid asn1_type_dot2Psid_24

typedef int dot2Psid_25;

extern const ASN1CType asn1_type_dot2Psid_25[];

typedef dot2Psid_25 dot2CVPApplication14Psid;

#define asn1_type_dot2CVPApplication14Psid asn1_type_dot2Psid_25

typedef int dot2Psid_26;

extern const ASN1CType asn1_type_dot2Psid_26[];

typedef dot2Psid_26 dot2CVPApplication15Psid;

#define asn1_type_dot2CVPApplication15Psid asn1_type_dot2Psid_26

typedef int dot2Psid_27;

extern const ASN1CType asn1_type_dot2Psid_27[];

typedef dot2Psid_27 dot2CVPApplication16Psid;

#define asn1_type_dot2CVPApplication16Psid asn1_type_dot2Psid_27

typedef int dot2CrlSeries_1;

extern const ASN1CType asn1_type_dot2CrlSeries_1[];

typedef dot2CrlSeries_1 dot2EeEnrollmentCrlSeries;

#define asn1_type_dot2EeEnrollmentCrlSeries asn1_type_dot2CrlSeries_1

typedef int dot2CrlSeries_2;

extern const ASN1CType asn1_type_dot2CrlSeries_2[];

typedef dot2CrlSeries_2 dot2EeNonPseudonymCrlSeries;

#define asn1_type_dot2EeNonPseudonymCrlSeries asn1_type_dot2CrlSeries_2

typedef int dot2CrlSeries_3;

extern const ASN1CType asn1_type_dot2CrlSeries_3[];

typedef dot2CrlSeries_3 dot2ObePseudonymCrlSeries;

#define asn1_type_dot2ObePseudonymCrlSeries asn1_type_dot2CrlSeries_3

typedef int dot2CrlSeries_4;

extern const ASN1CType asn1_type_dot2CrlSeries_4[];

typedef dot2CrlSeries_4 dot2ScmsComponentCrlSeries;

#define asn1_type_dot2ScmsComponentCrlSeries asn1_type_dot2CrlSeries_4

typedef int dot2CrlSeries_5;

extern const ASN1CType asn1_type_dot2CrlSeries_5[];

typedef dot2CrlSeries_5 dot2ScmsSpclComponentCrlSeries;

#define asn1_type_dot2ScmsSpclComponentCrlSeries asn1_type_dot2CrlSeries_5

typedef struct dot2ToBeEncryptedGroupIndex {
  ASN1String padding;
  ASN1String groupIdentifier;
  dot2Uint32 j;
} dot2ToBeEncryptedGroupIndex;


extern const ASN1CType asn1_type_dot2ToBeEncryptedGroupIndex[];

typedef struct dot2ToBeEncryptedIndividualPLV {
  dot2IValue iValue;
  dot2PreLinkageValue plv;
} dot2ToBeEncryptedIndividualPLV;


extern const ASN1CType asn1_type_dot2ToBeEncryptedIndividualPLV[];

typedef struct dot2ToBeEncryptedGroupPLV {
  dot2IValue iValue;
  dot2Uint32 j;
  dot2PreLinkageValue plv;
} dot2ToBeEncryptedGroupPLV;


extern const ASN1CType asn1_type_dot2ToBeEncryptedGroupPLV[];

typedef struct dot2SignatureAndSignerIdentifier {
  dot2SignerIdentifier signer;
  dot2Signature signature;
} dot2SignatureAndSignerIdentifier;


extern const ASN1CType asn1_type_dot2SignatureAndSignerIdentifier[];

typedef struct dot2EncryptedGroupPlvAndHostInfo {
  dot2EncryptedGroupPLV encryptedGPLV;
  dot2Hostname hostname;
} dot2EncryptedGroupPlvAndHostInfo;


extern const ASN1CType asn1_type_dot2EncryptedGroupPlvAndHostInfo[];

typedef dot2ScmsError dot2ScopedComponentCertificateManagementError;

#define asn1_type_dot2ScopedComponentCertificateManagementError asn1_type_dot2ScmsError

typedef dot2ScmsError dot2ScopedEcaEndEntityError;

#define asn1_type_dot2ScopedEcaEndEntityError asn1_type_dot2ScmsError

typedef dot2ScmsError dot2ScopedLaMaError;

#define asn1_type_dot2ScopedLaMaError asn1_type_dot2ScmsError

typedef dot2ScmsError dot2ScopedMaRaError;

#define asn1_type_dot2ScopedMaRaError asn1_type_dot2ScmsError

typedef dot2BasePolicyFile dot2GlobalPolicyFile;

extern const ASN1CType asn1_type_dot2GlobalPolicyFile[];

typedef struct dot2LocalPolicyFile {
  dot2BasePolicyFile globalParameters;
  dot2BasePolicyFile localParamters;
} dot2LocalPolicyFile;


extern const ASN1CType asn1_type_dot2LocalPolicyFile[];

typedef enum {
  dot2PolicyFiles_globalPolicyFile,
  dot2PolicyFiles_localPolicyFile,
} dot2PolicyFiles_choice;

typedef struct dot2PolicyFiles {
  dot2PolicyFiles_choice choice;
  union {
    dot2GlobalPolicyFile globalPolicyFile;
    dot2LocalPolicyFile localPolicyFile;
  } u;
} dot2PolicyFiles;

extern const ASN1CType asn1_type_dot2PolicyFiles[];

typedef int dot2Uint8_38;

extern const ASN1CType asn1_type_dot2Uint8_38[];

typedef enum {
  dot2ScmsPDU_1_ccm,
  dot2ScmsPDU_1_eca_ee,
  dot2ScmsPDU_1_ee_ma,
  dot2ScmsPDU_1_ee_ra,
  dot2ScmsPDU_1_la_ma,
  dot2ScmsPDU_1_la_pca,
  dot2ScmsPDU_1_la_ra,
  dot2ScmsPDU_1_ma_pca,
  dot2ScmsPDU_1_ma_ra,
  dot2ScmsPDU_1_pca_ra,
  dot2ScmsPDU_1_ra_pg,
} dot2ScmsPDU_1_choice;

typedef struct dot2ScmsPDU_1 {
  dot2ScmsPDU_1_choice choice;
  union {
    dot2ScmsComponentCertificateManagementPDU ccm;
    dot2EcaEndEntityInterfacePDU eca_ee;
    dot2EndEntityMaInterfacePDU ee_ma;
    dot2EndEntityRaInterfacePDU ee_ra;
    dot2LaMaInterfacePDU la_ma;
    dot2LaPcaInterfacePDU la_pca;
    dot2LaRaInterfacePDU la_ra;
    dot2MaPcaInterfacePDU ma_pca;
    dot2MaRaInterfacePDU ma_ra;
    dot2PcaRaInterfacePDU pca_ra;
    dot2RaPgInterfacePDU ra_pg;
  } u;
} dot2ScmsPDU_1;

extern const ASN1CType asn1_type_dot2ScmsPDU_1[];

typedef struct dot2ScmsPDU {
  dot2Uint8_38 version;
  dot2ScmsPDU_1 content;
} dot2ScmsPDU;


extern const ASN1CType asn1_type_dot2ScmsPDU[];

typedef int dot2Uint8_39;

extern const ASN1CType asn1_type_dot2Uint8_39[];

typedef enum {
  dot2ScmsFile_1_cert_chain,
  dot2ScmsFile_1_policy,
} dot2ScmsFile_1_choice;

typedef struct dot2ScmsFile_1 {
  dot2ScmsFile_1_choice choice;
  union {
    dot2CertificateChainFiles cert_chain;
    dot2PolicyFiles policy;
  } u;
} dot2ScmsFile_1;

extern const ASN1CType asn1_type_dot2ScmsFile_1[];

typedef struct dot2ScmsFile {
  dot2Uint8_39 version;
  dot2ScmsFile_1 content;
} dot2ScmsFile;


extern const ASN1CType asn1_type_dot2ScmsFile[];

typedef dot2ScmsPDU dot2ScopedEeEnrollmentCertRequest;

#define asn1_type_dot2ScopedEeEnrollmentCertRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedEeEnrollmentCertResponse;

#define asn1_type_dot2ScopedEeEnrollmentCertResponse asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedMisbehaviorReport;

#define asn1_type_dot2ScopedMisbehaviorReport asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedEeRaCertRequest;

#define asn1_type_dot2ScopedEeRaCertRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedRaEeCertResponse;

#define asn1_type_dot2ScopedRaEeCertResponse asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedPseudonymCertProvisioningRequest;

#define asn1_type_dot2ScopedPseudonymCertProvisioningRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedPseudonymCertProvisioningAck;

#define asn1_type_dot2ScopedPseudonymCertProvisioningAck asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedIdCertProvisioningRequest;

#define asn1_type_dot2ScopedIdCertProvisioningRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedIdCertProvisioningAck;

#define asn1_type_dot2ScopedIdCertProvisioningAck asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedAppCertProvisioningRequest;

#define asn1_type_dot2ScopedAppCertProvisioningRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedAppCertProvisioningAck;

#define asn1_type_dot2ScopedAppCertProvisioningAck asn1_type_dot2ScmsPDU

typedef dot2ScmsFile dot2ScopedGlobalCertificateChainFile;

#define asn1_type_dot2ScopedGlobalCertificateChainFile asn1_type_dot2ScmsFile

typedef dot2ScmsFile dot2ScopedLocalCertificateChainFile;

#define asn1_type_dot2ScopedLocalCertificateChainFile asn1_type_dot2ScmsFile

typedef dot2ScmsFile dot2ScopedGlobalPolicyFile;

#define asn1_type_dot2ScopedGlobalPolicyFile asn1_type_dot2ScmsFile

typedef dot2ScmsFile dot2ScopedLocalPolicyFile;

#define asn1_type_dot2ScopedLocalPolicyFile asn1_type_dot2ScmsFile

typedef dot2ScmsPDU dot2ScopedAuthenticatedDownloadRequest;

#define asn1_type_dot2ScopedAuthenticatedDownloadRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedLIRequest;

#define asn1_type_dot2ScopedLIRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedLIReply;

#define asn1_type_dot2ScopedLIReply asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedLSRequest;

#define asn1_type_dot2ScopedLSRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedLSReply;

#define asn1_type_dot2ScopedLSReply asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedPcaLaKeyAgreementRequest;

#define asn1_type_dot2ScopedPcaLaKeyAgreementRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedLaPcaKeyAgreementResponse;

#define asn1_type_dot2ScopedLaPcaKeyAgreementResponse asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedPcaLaKeyAgreementAck;

#define asn1_type_dot2ScopedPcaLaKeyAgreementAck asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedRaLaIndividualPreLinkageValueRequest;

#define asn1_type_dot2ScopedRaLaIndividualPreLinkageValueRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedRaLaGroupPreLinkageValueRequest;

#define asn1_type_dot2ScopedRaLaGroupPreLinkageValueRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedLaRaPreLinkageValueResponse;

#define asn1_type_dot2ScopedLaRaPreLinkageValueResponse asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedMaPcaPreLinkageValueRequest;

#define asn1_type_dot2ScopedMaPcaPreLinkageValueRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedPcaMaPreLinkageValueResponse;

#define asn1_type_dot2ScopedPcaMaPreLinkageValueResponse asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedMaPcaHPCRRequest;

#define asn1_type_dot2ScopedMaPcaHPCRRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedPcaMaHPCRResponse;

#define asn1_type_dot2ScopedPcaMaHPCRResponse asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedBlacklistRequest;

#define asn1_type_dot2ScopedBlacklistRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedBlacklistResponse;

#define asn1_type_dot2ScopedBlacklistResponse asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedLCIRequest;

#define asn1_type_dot2ScopedLCIRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedLCIResponse;

#define asn1_type_dot2ScopedLCIResponse asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedRseObeIdBlacklistRequest;

#define asn1_type_dot2ScopedRseObeIdBlacklistRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedRseObeIdBlacklistResponse;

#define asn1_type_dot2ScopedRseObeIdBlacklistResponse asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedRaPcaCertificateRequest;

#define asn1_type_dot2ScopedRaPcaCertificateRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedPcaRaCertificateRequestReply;

#define asn1_type_dot2ScopedPcaRaCertificateRequestReply asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedRaPgPolicySignatureRequest;

#define asn1_type_dot2ScopedRaPgPolicySignatureRequest asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedRaPgPolicySignatureRequestReply;

#define asn1_type_dot2ScopedRaPgPolicySignatureRequestReply asn1_type_dot2ScmsPDU

typedef dot2ScmsPDU dot2ScopedCertificateRequest;

extern const ASN1CType asn1_type_dot2ScopedCertificateRequest[];

typedef struct dot2SignedCertificateRequest {
  dot2HashAlgorithm hashId;
  dot2ScopedCertificateRequest tbsRequest;
  dot2SignerIdentifier signer;
  dot2Signature signature;
} dot2SignedCertificateRequest;


extern const ASN1CType asn1_type_dot2SignedCertificateRequest[];

typedef dot2SecuredScmsPDU dot2SignedEeEnrollmentCertRequest;

#define asn1_type_dot2SignedEeEnrollmentCertRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedEeEnrollmentCertResponse;

#define asn1_type_dot2SignedEeEnrollmentCertResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredMisbehaviorReport;

#define asn1_type_dot2SecuredMisbehaviorReport asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedMisbehaviorReport;

#define asn1_type_dot2SignedMisbehaviorReport asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredRACertRequest;

#define asn1_type_dot2SecuredRACertRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredRACertResponse;

#define asn1_type_dot2SecuredRACertResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedPseudonymCertProvisioningRequest;

#define asn1_type_dot2SignedPseudonymCertProvisioningRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredPseudonymCertProvisioningRequest;

#define asn1_type_dot2SecuredPseudonymCertProvisioningRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedPseudonymCertProvisioningAck;

#define asn1_type_dot2SignedPseudonymCertProvisioningAck asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredPseudonymCertProvisioningAck;

#define asn1_type_dot2SecuredPseudonymCertProvisioningAck asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedIdCertProvisioningRequest;

#define asn1_type_dot2SignedIdCertProvisioningRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredIdCertProvisioningRequest;

#define asn1_type_dot2SecuredIdCertProvisioningRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedIdCertProvisioningAck;

#define asn1_type_dot2SignedIdCertProvisioningAck asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredIdCertProvisioningAck;

#define asn1_type_dot2SecuredIdCertProvisioningAck asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedAppCertProvisioningRequest;

#define asn1_type_dot2SignedAppCertProvisioningRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredAppCertProvisioningRequest;

#define asn1_type_dot2SecuredAppCertProvisioningRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedAppCertProvisioningAck;

#define asn1_type_dot2SignedAppCertProvisioningAck asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredAppCertProvisioningAck;

#define asn1_type_dot2SecuredAppCertProvisioningAck asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedAuthenticatedDownloadRequest;

#define asn1_type_dot2SignedAuthenticatedDownloadRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredAuthenticatedDownloadRequest;

#define asn1_type_dot2SecuredAuthenticatedDownloadRequest asn1_type_dot2SecuredScmsPDU

typedef dot2Ieee1609Dot2Data dot2SignedGlobalPolicyFile;

#define asn1_type_dot2SignedGlobalPolicyFile asn1_type_dot2Ieee1609Dot2Data

typedef dot2Ieee1609Dot2Data dot2SignedLocalPolicyFile;

#define asn1_type_dot2SignedLocalPolicyFile asn1_type_dot2Ieee1609Dot2Data

typedef dot2SecuredScmsPDU dot2SignedLIRequest;

#define asn1_type_dot2SignedLIRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredLIRequest;

#define asn1_type_dot2SecuredLIRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedLIReply;

#define asn1_type_dot2SignedLIReply asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredLIReply;

#define asn1_type_dot2SecuredLIReply asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedLSRequest;

#define asn1_type_dot2SignedLSRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredLSRequest;

#define asn1_type_dot2SecuredLSRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedLSReply;

#define asn1_type_dot2SignedLSReply asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredLSReply;

#define asn1_type_dot2SecuredLSReply asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedPcaLaKeyAgreementRequest;

#define asn1_type_dot2SignedPcaLaKeyAgreementRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedLaPcaKeyAgreementResponse;

#define asn1_type_dot2SignedLaPcaKeyAgreementResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedPcaLaKeyAgreementAck;

#define asn1_type_dot2SignedPcaLaKeyAgreementAck asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedRaLaIndividualPreLinkageValueRequest;

#define asn1_type_dot2SignedRaLaIndividualPreLinkageValueRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedRaLaGroupPreLinkageValueRequest;

#define asn1_type_dot2SignedRaLaGroupPreLinkageValueRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedLaRaPreLinkageValueResponse;

#define asn1_type_dot2SignedLaRaPreLinkageValueResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedMaPcaPreLinkageValueRequest;

#define asn1_type_dot2SignedMaPcaPreLinkageValueRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredMaPcaPreLinkageValueRequest;

#define asn1_type_dot2SecuredMaPcaPreLinkageValueRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedPcaMaPreLinkageValueResponse;

#define asn1_type_dot2SignedPcaMaPreLinkageValueResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredPcaMaPreLinkageValueResponse;

#define asn1_type_dot2SecuredPcaMaPreLinkageValueResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedMaPcaHPCRRequest;

#define asn1_type_dot2SignedMaPcaHPCRRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredMaPcaHPCRRequest;

#define asn1_type_dot2SecuredMaPcaHPCRRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedPcaMaHPCRResponse;

#define asn1_type_dot2SignedPcaMaHPCRResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredPcaMaHPCRResponse;

#define asn1_type_dot2SecuredPcaMaHPCRResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedBlacklistRequest;

#define asn1_type_dot2SignedBlacklistRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredBlacklistRequest;

#define asn1_type_dot2SecuredBlacklistRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedBlacklistResponse;

#define asn1_type_dot2SignedBlacklistResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredBlacklistResponse;

#define asn1_type_dot2SecuredBlacklistResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedRseObeIdBlacklistRequest;

#define asn1_type_dot2SignedRseObeIdBlacklistRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredRseObeIdBlacklistRequest;

#define asn1_type_dot2SecuredRseObeIdBlacklistRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedRseObeIdBlacklistResponse;

#define asn1_type_dot2SignedRseObeIdBlacklistResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredRseObeIdBlacklistResponse;

#define asn1_type_dot2SecuredRseObeIdBlacklistResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedLCIRequest;

#define asn1_type_dot2SignedLCIRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredLCIRequest;

#define asn1_type_dot2SecuredLCIRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedLCIResponse;

#define asn1_type_dot2SignedLCIResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredLCIResponse;

#define asn1_type_dot2SecuredLCIResponse asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredRaPcaCertificateRequest;

#define asn1_type_dot2SecuredRaPcaCertificateRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredPcaRaCertificateRequestReply;

#define asn1_type_dot2SecuredPcaRaCertificateRequestReply asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedRaPgPolicySignatureRequest;

#define asn1_type_dot2SignedRaPgPolicySignatureRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredRaPgPolicySignatureRequest;

#define asn1_type_dot2SecuredRaPgPolicySignatureRequest asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SignedRaPgPolicySignatureRequestReply;

#define asn1_type_dot2SignedRaPgPolicySignatureRequestReply asn1_type_dot2SecuredScmsPDU

typedef dot2SecuredScmsPDU dot2SecuredRaPgPolicySignatureRequestReply;

#define asn1_type_dot2SecuredRaPgPolicySignatureRequestReply asn1_type_dot2SecuredScmsPDU

typedef dot2ScmsPDU dot2ScopedElectorEndorsement;

#define asn1_type_dot2ScopedElectorEndorsement asn1_type_dot2ScmsPDU

typedef int dot2Uint8_40;

extern const ASN1CType asn1_type_dot2Uint8_40[];

typedef struct dot2ElectorSsp {
  dot2Uint8_40 version;
} dot2ElectorSsp;


extern const ASN1CType asn1_type_dot2ElectorSsp[];

typedef int dot2Uint8_41;

extern const ASN1CType asn1_type_dot2Uint8_41[];

typedef struct dot2RootCaSsp {
  dot2Uint8_41 version;
} dot2RootCaSsp;


extern const ASN1CType asn1_type_dot2RootCaSsp[];

typedef int dot2Uint8_42;

extern const ASN1CType asn1_type_dot2Uint8_42[];

typedef struct dot2PGSsp {
  dot2Uint8_42 version;
} dot2PGSsp;


extern const ASN1CType asn1_type_dot2PGSsp[];

typedef int dot2Uint8_43;

extern const ASN1CType asn1_type_dot2Uint8_43[];

typedef struct dot2IcaSsp {
  dot2Uint8_43 version;
} dot2IcaSsp;


extern const ASN1CType asn1_type_dot2IcaSsp[];

typedef int dot2Uint8_44;

extern const ASN1CType asn1_type_dot2Uint8_44[];

typedef struct dot2EcaSsp {
  dot2Uint8_44 version;
} dot2EcaSsp;


extern const ASN1CType asn1_type_dot2EcaSsp[];

typedef int dot2Uint8_45;

extern const ASN1CType asn1_type_dot2Uint8_45[];

typedef struct dot2PcaSsp {
  dot2Uint8_45 version;
} dot2PcaSsp;


extern const ASN1CType asn1_type_dot2PcaSsp[];

typedef int dot2Uint8_46;

extern const ASN1CType asn1_type_dot2Uint8_46[];

typedef struct dot2CrlSignerSsp {
  dot2Uint8_46 version;
} dot2CrlSignerSsp;


extern const ASN1CType asn1_type_dot2CrlSignerSsp[];

typedef int dot2Uint8_47;

extern const ASN1CType asn1_type_dot2Uint8_47[];

typedef struct dot2DcmSsp {
  dot2Uint8_47 version;
} dot2DcmSsp;


extern const ASN1CType asn1_type_dot2DcmSsp[];

typedef int dot2Uint8_48;

extern const ASN1CType asn1_type_dot2Uint8_48[];

typedef struct dot2LaSsp {
  dot2Uint8_48 version;
  dot2Uint16 laId;
} dot2LaSsp;


extern const ASN1CType asn1_type_dot2LaSsp[];

typedef int dot2Uint8_49;

extern const ASN1CType asn1_type_dot2Uint8_49[];

typedef struct dot2LopSsp {
  dot2Uint8_49 version;
} dot2LopSsp;


extern const ASN1CType asn1_type_dot2LopSsp[];

typedef int dot2Uint8_50;

extern const ASN1CType asn1_type_dot2Uint8_50[];

typedef struct dot2SequenceOfPsid {
  dot2Psid *tab;
  size_t count;
} dot2SequenceOfPsid;

extern const ASN1CType asn1_type_dot2SequenceOfPsid[];

typedef struct dot2MaSsp {
  dot2Uint8_50 version;
  dot2SequenceOfPsid relevantPsids;
} dot2MaSsp;


extern const ASN1CType asn1_type_dot2MaSsp[];

typedef int dot2Uint8_51;

extern const ASN1CType asn1_type_dot2Uint8_51[];

typedef struct dot2RaSsp {
  dot2Uint8_51 version;
} dot2RaSsp;


extern const ASN1CType asn1_type_dot2RaSsp[];

typedef enum {
  dot2ScmsSsp_elector,
  dot2ScmsSsp_root,
  dot2ScmsSsp_pg,
  dot2ScmsSsp_ica,
  dot2ScmsSsp_eca,
  dot2ScmsSsp_pca,
  dot2ScmsSsp_crl,
  dot2ScmsSsp_dcm,
  dot2ScmsSsp_la,
  dot2ScmsSsp_lop,
  dot2ScmsSsp_ma,
  dot2ScmsSsp_ra,
} dot2ScmsSsp_choice;

typedef struct dot2ScmsSsp {
  dot2ScmsSsp_choice choice;
  union {
    dot2ElectorSsp elector;
    dot2RootCaSsp root;
    dot2PGSsp pg;
    dot2IcaSsp ica;
    dot2EcaSsp eca;
    dot2PcaSsp pca;
    dot2CrlSignerSsp crl;
    dot2DcmSsp dcm;
    dot2LaSsp la;
    dot2LopSsp lop;
    dot2MaSsp ma;
    dot2RaSsp ra;
  } u;
} dot2ScmsSsp;

extern const ASN1CType asn1_type_dot2ScmsSsp[];

typedef int dot2Uint3;

extern const ASN1CType asn1_type_dot2Uint3[];

typedef int dot2NinetyDegreeInt_1;

enum {
  dot2NinetyDegreeInt_1_min = -900000000,
  dot2NinetyDegreeInt_1_max = 900000000,
  dot2NinetyDegreeInt_1_unknown = 900000001,
};

extern const ASN1CType asn1_type_dot2NinetyDegreeInt_1[];

typedef dot2NinetyDegreeInt_1 dot2KnownLatitude;

#define asn1_type_dot2KnownLatitude asn1_type_dot2NinetyDegreeInt_1

typedef int dot2NinetyDegreeInt_2;

enum {
  dot2NinetyDegreeInt_2_min = -900000000,
  dot2NinetyDegreeInt_2_max = 900000000,
  dot2NinetyDegreeInt_2_unknown = 900000001,
};

extern const ASN1CType asn1_type_dot2NinetyDegreeInt_2[];

typedef dot2NinetyDegreeInt_2 dot2UnknownLatitude;

#define asn1_type_dot2UnknownLatitude asn1_type_dot2NinetyDegreeInt_2

typedef int dot2OneEightyDegreeInt_1;

enum {
  dot2OneEightyDegreeInt_1_min = -1799999999,
  dot2OneEightyDegreeInt_1_max = 1800000000,
  dot2OneEightyDegreeInt_1_unknown = 1800000001,
};

extern const ASN1CType asn1_type_dot2OneEightyDegreeInt_1[];

typedef dot2OneEightyDegreeInt_1 dot2KnownLongitude;

#define asn1_type_dot2KnownLongitude asn1_type_dot2OneEightyDegreeInt_1

typedef int dot2OneEightyDegreeInt_2;

enum {
  dot2OneEightyDegreeInt_2_min = -1799999999,
  dot2OneEightyDegreeInt_2_max = 1800000000,
  dot2OneEightyDegreeInt_2_unknown = 1800000001,
};

extern const ASN1CType asn1_type_dot2OneEightyDegreeInt_2[];

typedef dot2OneEightyDegreeInt_2 dot2UnknownLongitude;

#define asn1_type_dot2UnknownLongitude asn1_type_dot2OneEightyDegreeInt_2

typedef int dot2Uint8_52;

extern const ASN1CType asn1_type_dot2Uint8_52[];

typedef struct dot2CaCertP2pPDU {
  dot2Certificate *tab;
  size_t count;
} dot2CaCertP2pPDU;

extern const ASN1CType asn1_type_dot2CaCertP2pPDU[];

typedef enum {
  dot2Ieee1609dot2Peer2PeerPDU_1_caCerts,
} dot2Ieee1609dot2Peer2PeerPDU_1_choice;

typedef struct dot2Ieee1609dot2Peer2PeerPDU_1 {
  dot2Ieee1609dot2Peer2PeerPDU_1_choice choice;
  union {
    dot2CaCertP2pPDU caCerts;
  } u;
} dot2Ieee1609dot2Peer2PeerPDU_1;

extern const ASN1CType asn1_type_dot2Ieee1609dot2Peer2PeerPDU_1[];

typedef struct dot2Ieee1609dot2Peer2PeerPDU {
  dot2Uint8_52 version;
  dot2Ieee1609dot2Peer2PeerPDU_1 content;
} dot2Ieee1609dot2Peer2PeerPDU;


extern const ASN1CType asn1_type_dot2Ieee1609dot2Peer2PeerPDU[];

typedef int dot2Uint8_55;

extern const ASN1CType asn1_type_dot2Uint8_55[];

typedef struct dot2CrlPriorityInfo {
  BOOL priority_option;
  dot2Uint8 priority;
} dot2CrlPriorityInfo;


extern const ASN1CType asn1_type_dot2CrlPriorityInfo[];

typedef struct dot2HashBasedRevocationInfo {
  dot2HashedId10 id;
  dot2Time32 expiry;
} dot2HashBasedRevocationInfo;


extern const ASN1CType asn1_type_dot2HashBasedRevocationInfo[];

typedef struct dot2SequenceOfHashBasedRevocationInfo {
  dot2HashBasedRevocationInfo *tab;
  size_t count;
} dot2SequenceOfHashBasedRevocationInfo;

extern const ASN1CType asn1_type_dot2SequenceOfHashBasedRevocationInfo[];

typedef struct dot2ToBeSignedHashIdCrl {
  dot2Uint32 crlSerial;
  dot2SequenceOfHashBasedRevocationInfo entries;
} dot2ToBeSignedHashIdCrl;


extern const ASN1CType asn1_type_dot2ToBeSignedHashIdCrl[];

typedef struct dot2IndividualRevocation {
  dot2LinkageSeed linkage_seed1;
  dot2LinkageSeed linkage_seed2;
} dot2IndividualRevocation;


extern const ASN1CType asn1_type_dot2IndividualRevocation[];

typedef struct dot2SequenceOfIndividualRevocation {
  dot2IndividualRevocation *tab;
  size_t count;
} dot2SequenceOfIndividualRevocation;

extern const ASN1CType asn1_type_dot2SequenceOfIndividualRevocation[];

typedef struct dot2IMaxGroup {
  dot2Uint16 iMax;
  dot2SequenceOfIndividualRevocation contents;
} dot2IMaxGroup;


extern const ASN1CType asn1_type_dot2IMaxGroup[];

typedef struct dot2SequenceOfIMaxGroup {
  dot2IMaxGroup *tab;
  size_t count;
} dot2SequenceOfIMaxGroup;

extern const ASN1CType asn1_type_dot2SequenceOfIMaxGroup[];

typedef struct dot2LAGroup {
  dot2LaId la1Id;
  dot2LaId la2Id;
  dot2SequenceOfIMaxGroup contents;
} dot2LAGroup;


extern const ASN1CType asn1_type_dot2LAGroup[];

typedef struct dot2SequenceOfLAGroup {
  dot2LAGroup *tab;
  size_t count;
} dot2SequenceOfLAGroup;

extern const ASN1CType asn1_type_dot2SequenceOfLAGroup[];

typedef struct dot2JMaxGroup {
  dot2Uint8 jmax;
  dot2SequenceOfLAGroup contents;
} dot2JMaxGroup;


extern const ASN1CType asn1_type_dot2JMaxGroup[];

typedef struct dot2SequenceOfJMaxGroup {
  dot2JMaxGroup *tab;
  size_t count;
} dot2SequenceOfJMaxGroup;

extern const ASN1CType asn1_type_dot2SequenceOfJMaxGroup[];

typedef struct dot2GroupCrlEntry {
  dot2Uint16 iMax;
  dot2LaId la1Id;
  dot2LinkageSeed linkageSeed1;
  dot2LaId la2Id;
  dot2LinkageSeed linkageSeed2;
} dot2GroupCrlEntry;


extern const ASN1CType asn1_type_dot2GroupCrlEntry[];

typedef struct dot2SequenceOfGroupCrlEntry {
  dot2GroupCrlEntry *tab;
  size_t count;
} dot2SequenceOfGroupCrlEntry;

extern const ASN1CType asn1_type_dot2SequenceOfGroupCrlEntry[];

typedef struct dot2ToBeSignedLinkageValueCrl {
  dot2IValue iRev;
  dot2Uint8 indexWithinI;
  BOOL individual_option;
  dot2SequenceOfJMaxGroup individual;
  BOOL groups_option;
  dot2SequenceOfGroupCrlEntry groups;
} dot2ToBeSignedLinkageValueCrl;


extern const ASN1CType asn1_type_dot2ToBeSignedLinkageValueCrl[];

typedef enum {
  dot2CrlContents_1_fullHashCrl,
  dot2CrlContents_1_deltaHashCrl,
  dot2CrlContents_1_fullLinkedCrl,
  dot2CrlContents_1_deltaLinkedCrl,
} dot2CrlContents_1_choice;

typedef struct dot2CrlContents_1 {
  dot2CrlContents_1_choice choice;
  union {
    dot2ToBeSignedHashIdCrl fullHashCrl;
    dot2ToBeSignedHashIdCrl deltaHashCrl;
    dot2ToBeSignedLinkageValueCrl fullLinkedCrl;
    dot2ToBeSignedLinkageValueCrl deltaLinkedCrl;
  } u;
} dot2CrlContents_1;

extern const ASN1CType asn1_type_dot2CrlContents_1[];

typedef struct dot2CrlContents {
  dot2Uint8_55 version;
  dot2CrlSeries crlSeries;
  dot2HashedId8 cracaId;
  dot2Time32 issueDate;
  dot2Time32 nextCrl;
  dot2CrlPriorityInfo priorityInfo;
  dot2CrlContents_1 typeSpecific;
} dot2CrlContents;


extern const ASN1CType asn1_type_dot2CrlContents[];

typedef int dot2Psid_28;

extern const ASN1CType asn1_type_dot2Psid_28[];

typedef dot2Psid_28 dot2CrlPsid;

#define asn1_type_dot2CrlPsid asn1_type_dot2Psid_28

typedef int dot2Uint8_56;

extern const ASN1CType asn1_type_dot2Uint8_56[];

typedef enum dot2CracaType {
  dot2CracaType_isCraca,
  dot2CracaType_issuerIsCraca,
} dot2CracaType;

extern const ASN1CType asn1_type_dot2CracaType[];

typedef struct dot2PermissibleCrls {
  dot2CrlSeries *tab;
  size_t count;
} dot2PermissibleCrls;

extern const ASN1CType asn1_type_dot2PermissibleCrls[];

typedef struct dot2CrlSsp {
  dot2Uint8_56 version;
  dot2CracaType associatedCraca;
  dot2PermissibleCrls crls;
} dot2CrlSsp;


extern const ASN1CType asn1_type_dot2CrlSsp[];

#ifdef  __cplusplus
}
#endif

#endif /* _FFASN1_FFASN1_DOT2_2021_H */
