/**
 * \file parser.h
 *
 * Certificate Parser.  The Certificate Parser provides a directed mechanism
 * for parsing a certificate.  It supports raw mode, which allows a freeform
 * certificate to be parsed, and contract mode, in which a certificate must be
 * strictly parsed following a contract.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_PARSER_HEADER_GUARD
#define VCCERT_PARSER_HEADER_GUARD

#include <stdbool.h>
#include <stdint.h>
#include <vccrypt/suite.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/* sizes for fields in a certificate */
#define FIELD_TYPE_SIZE 2
#define FIELD_SIZE_SIZE 2

/* forward declaration for parser options. */
struct vccert_parser_options;

/* forward declaration for parser context. */
struct vccert_parser_context;

#define PARSER_ATTEST_ERROR_MISSING_SIGNER_UUID 0x1002
#define PARSER_ATTEST_ERROR_MISSING_SIGNATURE 0x1003
#define PARSER_ATTEST_ERROR_MISSING_SIGNING_CERT 0x1004
#define PARSER_ATTEST_ERROR_CHAIN_ATTESTATION 0x1005
#define PARSER_ATTEST_ERROR_SIGNER_UUID_MISMATCH 0x1006
#define PARSER_ATTEST_ERROR_SIGNER_MISSING_SIGNING_KEY 0x1007
#define PARSER_ATTEST_ERROR_SIGNATURE_MISMATCH 0x1008
#define PARSER_ATTEST_ERROR_GENERAL 0x1101

/**
 * Contract function pointer.
 *
 * A contract function examines a certificate and performs attestation rules
 * above and beyond the basic signing entity certificate chain walk performed by
 * the initial parser.  This contract function may cause additional certificates
 * to be parsed, and may recursively call into the parser options to test the
 * contract associated with a given artifact.
 */
typedef bool (*vccert_contract_fn_t)(
    struct vccert_parser_options* options,
    struct vccert_parser_context* context);

/**
 * Entity resolver function pointer.
 *
 * Look up the entity certificate associated with the given UUID.  Note that
 * the entity UUID must match the values provided to this callback.
 * The callback updates the pointer to the buffer provided to point to a
 * copy of this certificate and the Boolean flag to indicate whether this
 * certificate can be trusted or must also be attested.  Note that when used
 * in conjunction with a blockchain structure, the current state of the
 * blockchain should be consulted in order to ensure that the requested
 * entity is in a live state
 *
 * \param options           Opaque pointer to this options structure.
 * \param parser            Opaque pointer to the parser context.
 * \param entity_id         A pointer to the buffer holding the 128-bit
 *                          entity UUID for the entity certificate.
 * \param output_buffer     A pointer to a vccrypt_buffer_t buffer that
 *                          should be allocated with a copy of the requested
 *                          entity on success.
 * \param trusted           A pointer to a boolean flag that should be set
 *                          to true if this entity certificate can be
 *                          implicitly trusted, and false it if should be
 *                          further tested.  NOTE: this flag should ONLY be
 *                          set to true if this certificate previously
 *                          passed the attestation process.  Otherwise, it
 *                          MUST BE ATTESTED.
 *
 * \returns true if the entity certificate was found, and false otherwise.
 */
typedef bool (*vccert_parser_entity_resolver_t)(
    void* options, void* parser, const uint8_t* entity_id,
    vccrypt_buffer_t* output_buffer, bool* trusted);

/**
 * Entity state resolver.
 *
 * Get the state of the entity at the current time frame.
 *
 * \param options           Opaque pointer to this options structure.
 * \param parser            Opaque pointer to the parser context.
 * \param entity_id         A pointer to the buffer holding the 128-bit
 *                          entity UUID for the entity in question.
 *
 * \returns -1 if the entity cannot be found or if the entity state is
 * unknown.  Otherwise, returns the state of the entity as a numerical
 * offset into its state buffer.
 */
typedef int32_t (*vccert_parser_entity_state_resolver_t)(
    void* options, void* parser, const uint8_t* entity_id);

/**
 * Contract function resolver.
 *
 * Get the contract function associated with the given certificate type UUID.
 * This contract function will be used to perform further attestation of
 * this certificate.
 *
 * \param options           Opaque pointer to this options structure.
 * \param parser            Opaque pointer to the parser context.
 * \param type_id           A pointer to the buffer holding the 128-bit
 *                          certificate type ID for this certificate.
 * \param entity_id         A pointer to the buffer holding the 128-bit
 *                          entity UUID for the entity in question.
 *
 * \returns a valid contract function on success, and NULL on failure.
 */
typedef vccert_contract_fn_t (*vccert_parser_contract_resolver_t)(
    void* options, void* parser, const uint8_t* type_id,
    const uint8_t* entity_id);

/**
 * The parser options callback structure is used to manage callbacks needed to
 * parse a certificate.  In particular, certificate attestation is a recursive
 * process that requires walking a certificate chain back to a root certificate.
 * In order to facilitate a faster certificate attestation process, it is
 * possible to signal the parser that a given certificate in the chain has
 * already been verified.  This optimization should be used carefully, because
 * using it incorrectly WILL BREAK THE SECURITY OF THE SYSTEM.
 */
typedef struct vccert_parser_options
{
    /* this options structure inherits from disposable. */
    disposable_t hdr;

    /* the allocator options to use for this parser. */
    allocator_options_t* alloc_opts;

    /* the crypto suite to use for this parser. */
    vccrypt_suite_options_t* crypto_suite;

    /* entity resolver */
    vccert_parser_entity_resolver_t parser_options_entity_resolver;

    /* entity state resolver */
    vccert_parser_entity_state_resolver_t parser_options_entity_state_resolver;

    /* contract resolver */
    vccert_parser_contract_resolver_t parser_options_contract_resolver;

    /**
     * Options-specific context.
     */
    void* context;

} vccert_parser_options_t;

/**
 * The parser context manages attesting and parsing a certificate.
 */
typedef struct vccert_parser_context
{
    /* this is a disposable structure */
    disposable_t hdr;

    /* options structure for this parser */
    vccert_parser_options_t* options;
    /* raw pointer to the certificate */
    const uint8_t* cert;
    /* raw size of the certificate */
    size_t raw_size;
    /* attested size of the certificate */
    size_t size;

    /* back-tracking support for attestation */
    vccrypt_buffer_t parent_buffer;
    struct vccert_parser_context* parent;

} vccert_parser_context_t;

/**
 * Initialize a parser options structure using the given allocator, crypto
 * suite, and callback methods.  This options structure is owned by the caller
 * and must be disposed of when no longer needed by calling dispose().
 *
 * \param options           The options structure to initialize.
 * \param alloc_opts        The allocator options to use for this structure.
 * \param crypto_suite      The crypto suite to use for this structure.
 * \param entity_resolver   The entity resolver to use for this structure.
 * \param entity_state      The entity state resolver to use for this structure.
 * \param contract_resolver The contract resolver to use for this structure.
 * \param context           The user-specific context to use for this structure.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_parser_options_init(
    vccert_parser_options_t* options, allocator_options_t* alloc_opts,
    vccrypt_suite_options_t* crypto_suite,
    vccert_parser_entity_resolver_t entity_resolver,
    vccert_parser_entity_state_resolver_t entity_state,
    vccert_parser_contract_resolver_t contract_resolver, void* context);

/**
 * Initialize a parser context structure using the given options.
 *
 * \param options           The options structure to initialize.
 * \param context           The parser context structure to initialize.
 * \param cert              A pointer to the raw certificate to parse.
 * \param size              The size of the certificate to parse.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_parser_init(
    vccert_parser_options_t* options, vccert_parser_context_t* context,
    const void* cert, size_t size);

/**
 * Perform attestation on a certificate.
 *
 * \param context           The parser context structure holding the certificate
 *                          on which attestation should be performed.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_parser_attest(vccert_parser_context_t* context);

/**
 * Return the first field in the certificate.  If the certificate has not been
 * attested, then this performs an UNSAFE SEARCH of the RAW CERTIFICATE.  Run
 * vccert_parser_attest() first if you want trusted information.  Additional
 * fields can be found by calling vccert_parser_field_next().
 *
 * \param context           The parser context structure for this certificate.
 * \param field_id          The pointer to receive the short-hand field
 *                          identifier.
 * \param value             The pointer to receive a pointer to the field value.
 * \param size              The pointer to receive the size of this field.
 *
 * \returns 0 on success and non-zero if no fields exist in this certificate.
 */
int vccert_parser_field_first(
    vccert_parser_context_t* context, uint16_t* field_id,
    const uint8_t** value, size_t* size);

/**
 * Return the next field in the certificate.  If the certificate has not been
 * attested, then this performs an UNSAFE SEARCH of the RAW CERTIFICATE.  Run
 * vccert_parser_attest() first if you want trusted information.  Additional
 * fields can be found by calling vccert_parser_field_next().  The value pointer
 * should be pointing to a valid field in this certificate.  It will be used to
 * compute the offset of the next field in the certificate.
 *
 * \param context           The parser context structure for this certificate.
 * \param field_id          The pointer to receive the short-hand field
 *                          identifier.
 * \param value             The pointer to receive a pointer to the field value.
 *                          This pointer should be set to a valid field value in
 *                          the certificate.
 * \param size              The pointer to receive the size of this field.
 *
 * \returns 0 on success and non-zero if no fields exist in this certificate.
 */
int vccert_parser_field_next(
    vccert_parser_context_t* context, uint16_t* field_id,
    const uint8_t** value, size_t* size);

/**
 * Attempt to find the first occurrence of a field with the given short-hand
 * identifier in the certificate. If the certificate has not been attested, then
 * this performs an UNSAFE SEARCH of the RAW CERTIFICATE.  Run
 * vccert_parser_attest() first if you want trusted information.  Additional
 * matching fields can be found by calling vccert_parser_find_next().
 *
 * \param context           The parser context structure for this certificate.
 * \param field_id          The short-hand field identifier to find.
 * \param value             A pointer to the pointer to receive the value if the
 *                          field is found.
 * \param size              A pointer to receive the field size if the field is
 *                          found.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_parser_find_short(
    vccert_parser_context_t* context, uint16_t field_id,
    const uint8_t** value, size_t* size);

/**
 * Attempt to find the first field with the given UUID identifier in the
 * certificate. If the certificate has not been attested, then this performs an
 * UNSAFE SEARCH of the RAW CERTIFICATE.  Run vccert_parser_attest() first if
 * you want trusted information.  Additional matching fields can be found by
 * calling vccert_parser_find_next().
 *
 * \param context           The parser context structure for this certificate.
 * \param field_id          A pointer to the UUID value to find.
 * \param value             A pointer to the pointer to receive the value if the
 *                          field is found.
 * \param size              A pointer to receive the field size if the field is
 *                          found.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_parser_find(
    vccert_parser_context_t* context, const uint8_t* field_id,
    const uint8_t** value, size_t* size);

/**
 * Attempt to find the next occurrence of a field with the same short-hand
 * identifier as the current field in the certificate. If the certificate has
 * not been attested, then this performs an UNSAFE SEARCH of the RAW
 * CERTIFICATE.  Run vccert_parser_attest() first if you want trusted
 * information.
 *
 * \param context           The parser context structure for this certificate.
 * \param value             A pointer to the pointer of the current field.  This
 *                          will be updated with the next field with the same
 *                          field type ID.
 * \param size              A pointer to receive the field size if the field is
 *                          found.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_parser_find_next(
    vccert_parser_context_t* context, const uint8_t** value, size_t* size);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_PARSER_HEADER_GUARD
