/**
 * \file vccert_builder_emit.c
 *
 * Emit a certificate buffer and size from the builder.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "builder_internal.h"

/**
 * \brief Get a pointer to the current certificate and its size.
 *
 * The certificate pointer is owned by the builder context structure and will be
 * disposed when the structure is disposed.  If the caller wishes to keep the
 * certificate beyond the scope of the builder context, it should copy this
 * certificate data.
 *
 * \param context           The builder context to use for this operation.
 * \param size              A pointer to a size_t field to receive the current
 *                          size of the certificate.
 *
 * \returns a pointer to the raw certificate.
 */
const uint8_t* vccert_builder_emit(
    vccert_builder_context_t* context, size_t* size)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->builder.data != NULL);
    MODEL_ASSERT(context->builder.size >= context->offset);
    MODEL_ASSERT(size != NULL);

    /* set the size to the current offset */
    *size = context->offset;

    return (const uint8_t*)context->buffer.data;
}
