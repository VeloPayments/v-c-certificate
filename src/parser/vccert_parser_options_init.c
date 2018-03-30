/**
 * \file vccert_parser_options_init.c
 *
 * Initialize a certificate parser options structure for use for parsing and
 * attesting certificates.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "parser_internal.h"

/* forward decls */
static void vccert_parser_options_dispose(void* options);

/**
 * Initialize a parser options structure using the given allocator, crypto
 * suite, and callback methods.  This options structure is owned by the caller
 * and must be disposed of when no longer needed by calling dispose().
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
 * \returns 0 on success and non-zero on failure.
 */
int vccert_parser_options_init(
    vccert_parser_options_t* options, allocator_options_t* alloc_opts,
    vccrypt_suite_options_t* crypto_suite,
    vccert_parser_transaction_resolver_t txn_resolver,
    vccert_parser_artifact_state_resolver_t artifact_state,
    vccert_parser_contract_resolver_t contract_resolver,
    vccert_parser_entity_key_resolver_t key_resolver, void* context)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(crypto_suite != NULL);
    MODEL_ASSERT(txn_resolver != NULL);
    MODEL_ASSERT(artifact_state != NULL);
    MODEL_ASSERT(contract_resolver != NULL);
    MODEL_ASSERT(key_resolver != NULL);

    if (options == NULL || alloc_opts == NULL || crypto_suite == NULL || txn_resolver == NULL || artifact_state == NULL || contract_resolver == NULL || key_resolver == NULL)
    {
        return VCCERT_ERROR_PARSER_OPTIONS_INIT_INVALID_ARG;
    }

    options->hdr.dispose = &vccert_parser_options_dispose;
    options->alloc_opts = alloc_opts;
    options->crypto_suite = crypto_suite;
    options->parser_options_transaction_resolver = txn_resolver;
    options->parser_options_artifact_state_resolver = artifact_state;
    options->parser_options_contract_resolver = contract_resolver;
    options->parser_options_entity_key_resolver = key_resolver;
    options->context = context;

    /* success */
    return VCCERT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure by clearing it.
 *
 * \param options       The options structure to dispose.
 */
static void vccert_parser_options_dispose(void* options)
{
    memset(options, 0, sizeof(vccert_parser_options_t));
}
