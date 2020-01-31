/**
 * \file parser.h
 *
 * \brief The Certificate Parser provides a directed mechanism for parsing a
 * certificate.
 *
 * It supports raw mode, which allows a freeform certificate to be parsed, and
 * contract mode, in which a certificate must be strictly parsed following a
 * contract.
 *
 * \copyright 2017-2018 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_PARSER_HEADER_GUARD
#define VCCERT_PARSER_HEADER_GUARD

#include <stdbool.h>
#include <stdint.h>
#include <vccert/error_codes.h>
#include <vccrypt/suite.h>
#include <vpr/allocator.h>
#include <vpr/disposable.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * \defgroup ParserFieldConstants Constants related to parser fields.
 *
 * @{
 */

/**
 * \brief Size of the Field Type.
 */
#define FIELD_TYPE_SIZE 2

/**
 * \brief Size of the Field Size.
 */
#define FIELD_SIZE_SIZE 2
/**
 * @}
 */

/* forward declaration for parser options. */
struct vccert_parser_options;

/* forward declaration for parser context. */
struct vccert_parser_context;

/* forward declaration for contract closure. */
struct vccert_contract_closure;
typedef struct vccert_contract_closure vccert_contract_closure_t;

/**
 * \brief Looks up the last transaction certificate associated with the given
 * artifact UUID.
 *
 * Note that the artifact UUID must match the values provided to this callback.
 * The callback updates the pointer to the buffer provided to point to a copy of
 * this certificate and the Boolean flag to indicate whether this certificate
 * can be trusted or must also be attested.  Optionally, a transaction UUID can
 * be provided to pick an older transaction associated with this artifact.
 *
 * \param options           Opaque pointer to this options structure.
 * \param parser            Opaque pointer to the parser context.
 * \param artifact_id       A pointer to the buffer holding the 128-bit
 *                          artifact UUID.
 * \param txn_id            Either a pointer to a specific transaction UUID to
 *                          look up for this artifact, or NULL if the last
 *                          transaction should be queried.
 * \param output_buffer     A pointer to a vccrypt_buffer_t buffer that
 *                          should be allocated with a copy of the requested
 *                          transaction on success.
 * \param trusted           A pointer to a boolean flag that should be set
 *                          to true if this transaction certificate can be
 *                          implicitly trusted, and false it if should be
 *                          further tested.  NOTE: this flag should ONLY be
 *                          set to true if this certificate previously
 *                          passed the attestation process.  Otherwise, it
 *                          MUST BE ATTESTED.
 *
 * \returns the resolution status for this transaction.
 *      - true if the transaction certificate was found.
 *      - false if the transaction certificate was not found.
 */
typedef bool (*vccert_parser_transaction_resolver_t)(
    void* options, void* parser, const uint8_t* artifact_id,
    const uint8_t* txn_id, vccrypt_buffer_t* output_buffer,
    bool* trusted);

/**
 * \brief Get the state of the artifact at the current time frame.
 *
 * \param options           Opaque pointer to this options structure.
 * \param parser            Opaque pointer to the parser context.
 * \param artifact_id       A pointer to the buffer holding the 128-bit
 *                          artifact UUID for the entity in question.
 * \param txn_id            Optional pointer to a buffer to receive the last
 *                          transaction UUID associated with this artifact.
 *
 * \returns the state of this artifact.
 *      - -1 if the artifact cannot be found or if the artifact state is
 *        unknown.
 *      - Otherwise, returns the state of the artifact.
 */
typedef int32_t (*vccert_parser_artifact_state_resolver_t)(
    void* options, void* parser, const uint8_t* artifact_id,
    vccrypt_buffer_t* txn_id);

/**
 * \brief Initialize a contract closure that executes the contract for the given
 * transaction type.
 *
 * This contract closure will be used to perform further attestation of this
 * certificate.
 *
 * \param options           Opaque pointer to this options structure.
 * \param parser            Opaque pointer to the parser context.
 * \param type_id           A pointer to the buffer holding the 128-bit
 *                          transaction type ID for this certificate.
 * \param artifact_id       A pointer to the buffer holding the 128-bit
 *                          artifact UUID for the artifact in question.
 * \param closure           Pointer to the closure handle to be initialized with
 *                          this closure on success.  The caller owns this
 *                          closure and must dispose of it by calling
 *                          \ref dispose() when it is no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCCERT_STATUS_SUCCESS on success.
 */
typedef int (*vccert_parser_contract_resolver_t)(
    void* options, void* parser, const uint8_t* type_id,
    const uint8_t* artifact_id,
    vccert_contract_closure_t* closure);

/**
 * \brief Get the public portions of the encryption and signing keys for a given
 * entity.
 *
 * The implementation of this function is responsible for caching details about
 * a given entity from the blockchain, managing key rotation / change
 * operations, and managing expiry.
 *
 * \param options           Opaque pointer to this options structure.
 * \param parser            Opaque pointer to the parser context.
 * \param height            The blockchain height at the point when a given
 *                          entity is required.
 * \param entity_id         The entity ID to search for.
 * \param pubenckey_buffer  A buffer to receive the public encryption key.
 * \param pubsignkey_buffer A buffer to receive the public signing key.
 *
 * \returns true if the entity was found and false if the entity was not found.
 *          This return value represents the entity lifetime AT THE GIVEN BLOCK
 *          HEIGHT.  Likewise, the encrypting and signing keys populated were
 *          the keys used by that entity at that point.  This ensures that
 *          records are valid from a temporal perspective.
 */
typedef bool (*vccert_parser_entity_key_resolver_t)(
    void* options, void* parser, uint64_t height,
    const uint8_t* entity_id,
    vccrypt_buffer_t* pubenckey_buffer,
    vccrypt_buffer_t* pubsignkey_buffer);

/**
 * \brief The parser options callback structure is used to manage callbacks
 * needed to parse a certificate.
 *
 * In particular, certificate attestation is a recursive process that requires
 * walking a certificate chain back to a root certificate. In order to
 * facilitate a faster certificate attestation process, it is possible to signal
 * the parser that a given certificate in the chain has already been verified.
 * This optimization should be used carefully, because using it incorrectly WILL
 * BREAK THE SECURITY OF THE SYSTEM.
 */
typedef struct vccert_parser_options
{
    /**
     * \brief This options structure inherits from disposable.
     */
    disposable_t hdr;

    /**
     * \brief the allocator options to use for this parser.
     */
    allocator_options_t* alloc_opts;

    /**
     * \brief The crypto suite to use for this parser.
     */
    vccrypt_suite_options_t* crypto_suite;

    /**
     * \brief The transaction resolver to use for this parser.
     */
    vccert_parser_transaction_resolver_t parser_options_transaction_resolver;

    /**
     * \brief The artifact state resolver to use for this parser.
     */
    vccert_parser_artifact_state_resolver_t
        parser_options_artifact_state_resolver;

    /**
     * \brief The contract resolver to use for this parser.
     */
    vccert_parser_contract_resolver_t parser_options_contract_resolver;

    /**
     * \brief The entity public key resolver for this parser.
     */
    vccert_parser_entity_key_resolver_t parser_options_entity_key_resolver;

    /**
     * \brief Options-specific context.
     */
    void* context;

} vccert_parser_options_t;

/**
 * \brief The parser context manages attesting and parsing a certificate.
 */
typedef struct vccert_parser_context
{
    /**
     * \brief This is a disposable structure.
     */
    disposable_t hdr;

    /**
     * \brief The options structure for this parser.
     */
    vccert_parser_options_t* options;

    /**
     * \brief The raw pointer to the certificate.
     */
    const uint8_t* cert;

    /**
     * \brief The raw size of the certificate.
     */
    size_t raw_size;

    /**
     * \brief The attested size of the certificate.
     */
    size_t size;

    /**
     * \brief Back-tracking support for attestation.
     */
    vccrypt_buffer_t parent_buffer;

    /**
     * \brief The parent parser context, used for back-tracking.
     */
    struct vccert_parser_context* parent;

} vccert_parser_context_t;

/**
 * \brief The contract closure structure abstracts a way to "capture" variables
 * as context so it is possible to write more complex first-order functions in
 * C.
 */
struct vccert_contract_closure
{
    /**
     * \brief This is a disposable structure.
     */
    disposable_t hdr;

    /**
     * \brief The function pointer for the contract function.
     *
     * A contract function examines a certificate and performs attestation
     * rules above and beyond the basic signing entity certificate chain walk
     * performed by the initial parser.
     *
     * This contract function may cause additional certificates to be parsed,
     * and may recursively call into the parser options to test the contract
     * associated with a given artifact.
     *
     * \param parser  The \ref vccert_parser_context structure for this parser.
     *                The current parser context.
     * \param context The opaque user context provided by the closure structure.
     *
     * \returns the result of executing the contract.
     *      - true if this certificate passes the contract.
     *      - false if this cetificate fails the contract.
     */
    bool (*contract_fn)(vccert_parser_context_t* parser, void* context);

    /**
     * \brief The user-defined context for this closure.
     */
    void* context;
};

/**
 * \brief Initialize a parser options structure using the given allocator,
 * crypto suite, and callback methods.
 *
 * This options structure is owned by the caller and must be disposed of when no
 * longer needed by calling dispose().
 *
 * \param options           The options structure to initialize.
 * \param alloc_opts        The allocator options to use for this structure.
 * \param crypto_suite      The crypto suite to use for this structure.
 * \param txn_resolver      The transaction resolver to use for this structure.
 * \param artifact_state    The artifact state resolver to use for this
 *                          structure.
 * \param contract_resolver The contract resolver to use for this structure.
 * \param key_resolver      The entity key resolver to use for this structure.
 * \param context           The user-specific context to use for this structure.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_PARSER_OPTIONS_INIT_INVALID_ARG if an invalid
 *        argument was passed to vccert_parser_options_init().
 *      - a non-zero error code on failure.
 */
int vccert_parser_options_init(
    vccert_parser_options_t* options, allocator_options_t* alloc_opts,
    vccrypt_suite_options_t* crypto_suite,
    vccert_parser_transaction_resolver_t txn_resolver,
    vccert_parser_artifact_state_resolver_t artifact_state,
    vccert_parser_contract_resolver_t contract_resolver,
    vccert_parser_entity_key_resolver_t key_resolver, void* context);

/**
 * \brief Initialize a parser context structure using the given options.
 *
 * \param options           The options structure to initialize.
 * \param context           The parser context structure to initialize.
 * \param cert              A pointer to the raw certificate to parse.
 * \param size              The size of the certificate to parse.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_PARSER_INIT_INVALID_ARG if an invalid argument was
 *        passed to vccert_parser_init().
 *      - a non-zero error code on failure.
 */
int vccert_parser_init(
    vccert_parser_options_t* options, vccert_parser_context_t* context,
    const void* cert, size_t size);

/**
 * \brief Perform attestation on a certificate.
 *
 * \param context           The parser context structure holding the certificate
 *                          on which attestation should be performed.
 * \param height            The current height of the blockchani.
 * \param verifyContract    Set to true if the contract for the given
 *                          transaction should be verified.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_PARSER_ATTEST_MISSING_SIGNER_UUID if the signer UUID
 *        is missing from the certificate.
 *      - \ref VCCERT_ERROR_PARSER_ATTEST_MISSING_SIGNATURE if the signature is
 *        missing from the certificate.
 *      - \ref VCCERT_ERROR_PARSER_ATTEST_GENERAL if a general error occurred
 *        while attempting to attest this certificate.
 *      - \ref VCCERT_ERROR_PARSER_ATTEST_MISSING_SIGNING_CERT if the
 *        certificate containing the public signing key for the signing entity
 *        could not be resolved.
 *      - \ref VCCERT_ERROR_PARSER_ATTEST_SIGNATURE_MISMATCH if the computed
 *        signature did not match the signature in the certificate.
 *      - \ref VCCERT_ERROR_PARSER_ATTEST_MISSING_TRANSACTION_TYPE if the
 *        transaction type for this certificate could not be found.
 *      - \ref VCCERT_ERROR_PARSER_ATTEST_MISSING_ARTIFACT_ID if the artifact
 *        identifier for this transaction could not be found.
 *      - \ref VCCERT_ERROR_PARSER_ATTEST_MISSING_CONTRACT if the contract for
 *        this certificate could not be found.
 *      - \ref VCCERT_ERROR_PARSER_ATTEST_CONTRACT_VERIFICATION if contract
 *        verification for this certificate failed.
 *      - a non-zero error code on failure.
 */
int vccert_parser_attest(
    vccert_parser_context_t* context, uint64_t height, bool verifyContract);

/**
 * \brief Return the first field in the certificate.
 *
 * If the certificate has not been attested, then this performs an UNSAFE SEARCH
 * of the RAW CERTIFICATE.  Run vccert_parser_attest() first if you want trusted
 * information.  Additional fields can be found by calling
 * vccert_parser_field_next().
 *
 * \param context           The parser context structure for this certificate.
 * \param field_id          The pointer to receive the short-hand field
 *                          identifier.
 * \param value             The pointer to receive a pointer to the field value.
 * \param size              The pointer to receive the size of this field.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_ARG if an invalid argument is
 *        provided.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE if a field with an
 *        invalid size is encountered in the certificate.
 *      - a non-zero error code on failure.
 */
int vccert_parser_field_first(
    vccert_parser_context_t* context, uint16_t* field_id,
    const uint8_t** value, size_t* size);

/**
 * \brief Return the next field in the certificate.
 *
 * If the certificate has not been attested, then this performs an UNSAFE SEARCH
 * of the RAW CERTIFICATE.  Run vccert_parser_attest() first if you want trusted
 * information.  Additional fields can be found by calling
 * vccert_parser_field_next().  The value pointer should be pointing to a valid
 * field in this certificate.  It will be used to compute the offset of the next
 * field in the certificate.
 *
 * \param context           The parser context structure for this certificate.
 * \param field_id          The pointer to receive the short-hand field
 *                          identifier.
 * \param value             The pointer to receive a pointer to the field value.
 *                          This pointer should be set to a valid field value in
 *                          the certificate.
 * \param size              The pointer to receive the size of this field.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_NEXT_INVALID_FIELD_SIZE if a field with
 *        an invalid size is encountered in this certificate.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_NEXT_FIELD_NOT_FOUND if another field
 *        is not found.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_ARG if an invalid argument is
 *        provided.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE if a field with an
 *        invalid size is encountered in the certificate.
 *      - a non-zero error code on failure.
 */
int vccert_parser_field_next(
    vccert_parser_context_t* context, uint16_t* field_id,
    const uint8_t** value, size_t* size);

/**
 * \brief Attempt to find the first occurrence of a field with the given
 * short-hand identifier in the certificate.
 *
 * If the certificate has not been attested, then this performs an UNSAFE SEARCH
 * of the RAW CERTIFICATE.  Run vccert_parser_attest() first if you want trusted
 * information.  Additional matching fields can be found by calling
 * vccert_parser_find_next().
 *
 * \param context           The parser context structure for this certificate.
 * \param field_id          The short-hand field identifier to find.
 * \param value             A pointer to the pointer to receive the value if the
 *                          field is found.
 * \param size              A pointer to receive the field size if the field is
 *                          found.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_NEXT_INVALID_FIELD_SIZE if a field with
 *        an invalid size is encountered in this certificate.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_NEXT_FIELD_NOT_FOUND if another field
 *        is not found.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_ARG if an invalid argument is
 *        provided.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE if a field with an
 *        invalid size is encountered in the certificate.
 *      - a non-zero error code on failure.
 */
int vccert_parser_find_short(
    vccert_parser_context_t* context, uint16_t field_id,
    const uint8_t** value, size_t* size);

/**
 * \brief Attempt to find the first field with the given UUID identifier in the
 * certificate.
 *
 * If the certificate has not been attested, then this performs an UNSAFE SEARCH
 * of the RAW CERTIFICATE.  Run vccert_parser_attest() first if you want trusted
 * information.  Additional matching fields can be found by calling
 * vccert_parser_find_next().
 *
 * \param context           The parser context structure for this certificate.
 * \param field_id          A pointer to the UUID value to find.
 * \param value             A pointer to the pointer to receive the value if the
 *                          field is found.
 * \param size              A pointer to receive the field size if the field is
 *                          found.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_NEXT_INVALID_FIELD_SIZE if a field with
 *        an invalid size is encountered in this certificate.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_NEXT_FIELD_NOT_FOUND if another field
 *        is not found.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_ARG if an invalid argument is
 *        provided.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE if a field with an
 *        invalid size is encountered in the certificate.
 *      - a non-zero error code on failure.
 */
int vccert_parser_find(
    vccert_parser_context_t* context, const uint8_t* field_id,
    const uint8_t** value, size_t* size);

/**
 * \brief Attempt to find the next occurrence of a field with the same
 * short-hand identifier as the current field in the certificate.
 *
 * If the certificate has not been attested, then this performs an UNSAFE SEARCH
 * of the RAW CERTIFICATE.  Run vccert_parser_attest() first if you want trusted
 * information.
 *
 * \param context           The parser context structure for this certificate.
 * \param value             A pointer to the pointer of the current field.  This
 *                          will be updated with the next field with the same
 *                          field type ID.
 * \param size              A pointer to receive the field size if the field is
 *                          found.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_NEXT_INVALID_FIELD_SIZE if a field with
 *        an invalid size is encountered in this certificate.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_NEXT_FIELD_NOT_FOUND if another field
 *        is not found.
 *      - \ref VCCERT_ERROR_PARSER_FIND_NEXT_FIELD_NOT_FOUND if another field
 *        is not found.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_ARG if an invalid argument is
 *        provided.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE if a field with an
 *        invalid size is encountered in the certificate.
 *      - \ref VCCERT_ERROR_PARSER_FIND_NEXT_INVALID_FIELD_SIZE if a field
 *        with an invalid size is encountered in the certificate.
 *      - a non-zero error code on failure.
 */
int vccert_parser_find_next(
    vccert_parser_context_t* context, const uint8_t** value, size_t* size);

/**
 * \brief Call the given contract closure with the given parser context.
 *
 * \param closure           The closure to call.
 * \param parser            The parser context for this call.
 *
 * \returns the result of executing the contract.
 *      - true if this certificate passes the contract.
 *      - false if this certificate fails the contract.
 */
bool vccert_contract_closure_call(
    vccert_contract_closure_t* closure,
    vccert_parser_context_t* parser);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_PARSER_HEADER_GUARD
