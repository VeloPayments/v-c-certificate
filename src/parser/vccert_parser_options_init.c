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
    vccert_parser_contract_resolver_t contract_resolver, void* context)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(crypto_suite != NULL);
    MODEL_ASSERT(entity_resolver != NULL);
    MODEL_ASSERT(entity_state != NULL);
    MODEL_ASSERT(contract_resolver != NULL);

    if (options == NULL || alloc_opts == NULL || crypto_suite == NULL || entity_resolver == NULL || entity_state == NULL || contract_resolver == NULL)
    {
        return 1;
    }

    options->hdr.dispose = &vccert_parser_options_dispose;
    options->alloc_opts = alloc_opts;
    options->crypto_suite = crypto_suite;
    options->parser_options_entity_resolver = entity_resolver;
    options->parser_options_entity_state_resolver = entity_state;
    options->parser_options_contract_resolver = contract_resolver;
    options->context = context;

    /* success */
    return 0;
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
