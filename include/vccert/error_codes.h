/**
 * \file error_codes.h
 *
 * \brief Error codes for vccert.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_ERROR_CODES_HEADER_GUARD
#define VCCERT_ERROR_CODES_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup VCCertErrorcodes Error codes for the Velo Certificate Library.
 *
 * @{
 */

/**
 * \brief The \ref VCCERT_STATUS_SUCCESS code represents the successful
 * completion of a Velo Certificate Library method.
 */
#define VCCERT_STATUS_SUCCESS 0x0000

/**
 * \brief An attempt was made to call vccert_parser_options_init() with an
 * invalid argument.
 */
#define VCCERT_ERROR_PARSER_OPTIONS_INIT_INVALID_ARG 0x3100

/**
 * \brief An attempt was made to call vccert_parser_init() with an invalid
 * argument.
 */
#define VCCERT_ERROR_PARSER_INIT_INVALID_ARG 0x3104

/**
 * \brief The field size for the next field is invalid.
 */
#define VCCERT_ERROR_PARSER_FIELD_NEXT_INVALID_FIELD_SIZE 0x3108

/**
 * \brief A next field matching the given short code was not found.
 */
#define VCCERT_ERROR_PARSER_FIELD_NEXT_FIELD_NOT_FOUND 0x3109

/**
 * \brief An invalid argmument was passed to this method.
 */
#define VCCERT_ERROR_PARSER_FIELD_INVALID_ARG 0x310C

/**
 * \brief The field size in the certificate is invalid.
 */
#define VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE 0x310D

/**
 * \brief The signer UUID was not found during attestation.
 */
#define VCCERT_ERROR_PARSER_ATTEST_MISSING_SIGNER_UUID 0x3110

/**
 * \brief The signature was not found during attestation.
 */
#define VCCERT_ERROR_PARSER_ATTEST_MISSING_SIGNATURE 0x3111

/**
 * \brief The signing entity's certificate was not found during attestation.
 */
#define VCCERT_ERROR_PARSER_ATTEST_MISSING_SIGNING_CERT 0x3112

/**
 * \brief A certificate chain issue was encountered during attestation.
 */
#define VCCERT_ERROR_PARSER_ATTEST_CHAIN_ATTESTATION 0x3113

/**
 * \brief The signer UUID for the signing entity's certificate did not match the
 * UUID provided in the certificate being attested.
 */
#define VCCERT_ERROR_PARSER_ATTEST_SIGNER_UUID_MISMATCH 0x3114

/**
 * \brief The signing public key for the signer was not found.
 */
#define VCCERT_ERROR_PARSER_ATTEST_SIGNER_MISSING_SIGNING_KEY 0x3115

/**
 * \brief The emitted signature and the computed signature did not match.
 */
#define VCCERT_ERROR_PARSER_ATTEST_SIGNATURE_MISMATCH 0x3116

/**
 * \brief A contract was not found for this transaction.
 */
#define VCCERT_ERROR_PARSER_ATTEST_MISSING_CONTRACT 0x3117

/**
 * \brief Contract verification failed.
 */
#define VCCERT_ERROR_PARSER_ATTEST_CONTRACT_VERIFICATION 0x3118

/**
 * \brief The transaction type was not found.
 */
#define VCCERT_ERROR_PARSER_ATTEST_MISSING_TRANSACTION_TYPE 0x3119

/**
 * \brief The artifact ID was not found.
 */
#define VCCERT_ERROR_PARSER_ATTEST_MISSING_ARTIFACT_ID 0x311A

/**
 * \brief A general error occurred.
 */
#define VCCERT_ERROR_PARSER_ATTEST_GENERAL 0x3120

/**
 * \brief An invalid field size was encountered during
 * vccert_parser_find_next().
 */
#define VCCERT_ERROR_PARSER_FIND_NEXT_INVALID_FIELD_SIZE 0x3124

/**
 * \brief The requested field was not found in vccert_parser_find_next().
 */
#define VCCERT_ERROR_PARSER_FIND_NEXT_FIELD_NOT_FOUND 0x3125

/**
 * \brief An invalid argument was passed to vccert_builder_options_init().
 */
#define VCCERT_ERROR_BUILDER_OPTIONS_INIT_INVALID_ARG 0x3129

/**
 * \brief An invalid argument was passed to vccert_builder_init().
 */
#define VCCERT_ERROR_BUILDER_INIT_INVALID_ARG 0x312D

/**
 * \brief An invalid argument was passed to vccert_builder_sign().
 */
#define VCCERT_ERROR_BUILDER_SIGN_INVALID_ARG 0x3131

/**
 * \brief The emitted field size would be invalid.
 */
#define VCCERT_ERROR_BUILDER_SIGN_INVALID_FIELD_SIZE 0x3132

/**
 * \brief An invalid argument was provided to vccert_builder_add_*().
 */
#define VCCERT_ERROR_BUILDER_ADD_INVALID_ARG 0x3134

/**
 * @}
 */

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_ERROR_CODES_HEADER_GUARD
