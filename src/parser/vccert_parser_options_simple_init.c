/**
 * \file vccert_parser_options_simple_init.c
 *
 * Initialize a certificate parser options structure for use for parsing and
 * NOT attesting certificates.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "parser_internal.h"

/* forward decls. */
static bool dummy_txn_resolver(
    void* options, void* parser, const uint8_t* artifact_id,
    const uint8_t* txn_id, vccrypt_buffer_t* output_buffer, bool* trusted);
static int32_t dummy_artifact_state_resolver(
    void* options, void* parser, const uint8_t* artifact_id,
    vccrypt_buffer_t* txn_id);
static int dummy_contract_resolver(
    void* options, void* parser, const uint8_t* type_id,
    const uint8_t* artifact_id, vccert_contract_closure_t* closure);
static bool dummy_key_resolver(
    void* options, void* parser, uint64_t height, const uint8_t* entity_id,
    vccrypt_buffer_t* pubenckey_buffer, vccrypt_buffer_t* pubsignkey_buffer);

/**
 * \brief Initialize a parser options structure using the given allocator,
 * and crypto suite. This is a simplified initialization method, and the
 * resulting parser will always fail attestation.
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
int vccert_parser_options_simple_init(
    vccert_parser_options_t* options, allocator_options_t* alloc_opts,
    vccrypt_suite_options_t* crypto_suite)
{
    return
        vccert_parser_options_init(
            options, alloc_opts, crypto_suite, &dummy_txn_resolver,
            &dummy_artifact_state_resolver, &dummy_contract_resolver,
            &dummy_key_resolver, NULL);
}

/**
 * \brief Dummy transaction resolver.
 */
static bool dummy_txn_resolver(
    void* UNUSED(options), void* UNUSED(parser),
    const uint8_t* UNUSED(artifact_id),
    const uint8_t* UNUSED(txn_id), vccrypt_buffer_t* UNUSED(output_buffer),
    bool* UNUSED(trusted))
{
    return false;
}

/**
 * \brief Dummy artifact state resolver.
 */
static int32_t dummy_artifact_state_resolver(
    void* UNUSED(options), void* UNUSED(parser),
    const uint8_t* UNUSED(artifact_id), vccrypt_buffer_t* UNUSED(txn_id))
{
    return 0;
}

/**
 * \brief Dummy contract resolver.
 */
static int dummy_contract_resolver(
    void* UNUSED(options), void* UNUSED(parser), const uint8_t* UNUSED(type_id),
    const uint8_t* UNUSED(artifact_id),
    vccert_contract_closure_t* UNUSED(closure))
{
    return VCCERT_ERROR_PARSER_ATTEST_MISSING_CONTRACT;
}

/**
 * \brief Dummy key resolver.
 */
static bool dummy_key_resolver(
    void* UNUSED(options), void* UNUSED(parser), uint64_t UNUSED(height),
    const uint8_t* UNUSED(entity_id),
    vccrypt_buffer_t* UNUSED(pubenckey_buffer),
    vccrypt_buffer_t* UNUSED(pubsignkey_buffer))
{
    return false;
}
