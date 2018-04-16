/**
 * \file vccert_builder_options_init.c
 *
 * Initialize a certificate builder options structure for use in building and
 * signing certificates.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccert/builder.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccert_builder_options_dispose(void* options);

/**
 * \brief Initialize a builder options structure using the given allocator and
 * crypto suite.
 *
 * This options structure is owned by the caller and must be disposed of when no
 * longer needed by calling dispose().
 *
 * \param options           The options structure to initialize.
 * \param alloc_opts        The allocator options to use for this structure.
 * \param crypto_suite      The crypto suite to use for this structure.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_BUILDER_OPTIONS_INIT_INVALID_ARG if one of the
 *             arguments to this method is invalid.
 */
int vccert_builder_options_init(
    vccert_builder_options_t* options, allocator_options_t* alloc_opts,
    vccrypt_suite_options_t* crypto_suite)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(alloc_opts != NULL);
    MODEL_ASSERT(crypto_suite != NULL);

    /* parameter sanity check */
    if (options == NULL || alloc_opts == NULL || crypto_suite == NULL)
    {
        return VCCERT_ERROR_BUILDER_OPTIONS_INIT_INVALID_ARG;
    }

    options->hdr.dispose = &vccert_builder_options_dispose;
    options->alloc_opts = alloc_opts;
    options->crypto_suite = crypto_suite;

    /* success */
    return VCCERT_STATUS_SUCCESS;
}

/**
 * Dispose of the options structure by clearing it.
 *
 * \param options       The options structure to dispose.
 */
static void vccert_builder_options_dispose(void* options)
{
    memset(options, 0, sizeof(vccert_builder_options_t));
}
