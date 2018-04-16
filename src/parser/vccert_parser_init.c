/**
 * \file vccert_parser_init.c
 *
 * Initialize a certificate parser for use for parsing and attesting a
 * certificate.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "parser_internal.h"

/* forward decls */
static void vccert_parser_dispose(void* context);

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
    const void* cert, size_t size)
{
    MODEL_ASSERT(options != NULL);
    MODEL_ASSERT(options->alloc_opts != NULL);
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(cert != NULL);
    MODEL_ASSERT(size > 0);

    if (options == NULL || context == NULL || cert == NULL || size == 0)
    {
        return VCCERT_ERROR_PARSER_INIT_INVALID_ARG;
    }

    /* front matter for this context structure */
    context->hdr.dispose = &vccert_parser_dispose;
    context->options = options;

    /* Both the raw size and size start at the complete size of the */
    /* certificate. Once attestation has been performed, the size will be */
    /* trimmed to the attested size. */
    context->cert = cert;
    context->raw_size = size;
    context->size = size;

    /* The certificate context supports a recursive structure for managing */
    /* attestation.  Since certificate attestation might require the */
    /* verification of more than one certificate, this data structure */
    /* provides a means by which the attestation process can be restarted for */
    /* the parent certificates. */
    context->parent_buffer.data = NULL;
    context->parent_buffer.size = 0;
    context->parent = NULL;

    /* success */
    return VCCERT_STATUS_SUCCESS;
}

/**
 * Dispose of the parser context, recursively clearing it out if necessary.
 *
 * \param context       The parser context to clear.
 */
static void vccert_parser_dispose(void* context)
{
    vccert_parser_context_t* ctx = (vccert_parser_context_t*)context;
    vccert_parser_options_t* options = ctx->options;

    /* if the parent buffer was initialized, dispose it. */
    if (ctx->parent_buffer.data != NULL)
    {
        dispose((disposable_t*)&ctx->parent_buffer);
    }

    /* save the parent pointer for the recursive cleanup below. */
    ctx = ctx->parent;

    /* clear out the root context structure */
    memset(context, 0, sizeof(vccert_parser_context_t));

    /* recursively clear out the parent structures */
    while (ctx != NULL)
    {
        if (ctx->parent_buffer.data != NULL)
        {
            dispose((disposable_t*)&ctx->parent_buffer);
        }

        /* shuffle pointers so that we can release this structure and recurse */
        /* into the parent. */
        context = ctx;
        ctx = ctx->parent;

        /* release the child context */
        memset(context, 0, sizeof(vccert_parser_context_t));
        release(options->alloc_opts, context);
    }
}
