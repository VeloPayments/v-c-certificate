/**
 * \file vccert_builder_init.c
 *
 * Initialize a certificate builder structure for use in building and signing
 * certificates.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccert/builder.h>
#include <vpr/parameters.h>

/* forward decls */
static void vccert_builder_dispose(void* context);

/**
 * Initialize a builder context structure using the given options and maximum
 * size.
 *
 * \param options           The options structure to initialize.
 * \param context           The builder context structure to initialize.
 * \param size              The maximum size of the certificate.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_init(
    vccert_builder_options_t* options, vccert_builder_context_t* context,
    size_t size)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->alloc_opts != NULL);
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(size > 0);

    /* parameter sanity check */
    if (options == NULL || options->alloc_opts == NULL || options == NULL || size == 0)
    {
        return VCCERT_ERROR_BUILDER_INIT_INVALID_ARG;
    }

    /* initialize the context */
    context->hdr.dispose = &vccert_builder_dispose;
    context->options = options;
    context->offset = 0;

    /* allocate the buffer */
    return vccrypt_buffer_init(
        &context->buffer, options->alloc_opts, size);
}

/**
 * Dispose of the builder context structure.
 *
 * \param options       The options structure to dispose.
 */
static void vccert_builder_dispose(void* context)
{
    vccert_builder_context_t* ctx = (vccert_builder_context_t*)context;

    dispose((disposable_t*)&ctx->buffer);

    memset(ctx, 0, sizeof(vccert_builder_context_t));
}
