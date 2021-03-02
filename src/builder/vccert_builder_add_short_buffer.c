/**
 * \file vccert_builder_add_short_buffer.c
 *
 * Add a buffer field to a certificate.
 *
 * \copyright 2017-2021 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "builder_internal.h"

/**
 * \brief Add a byte buffer field to the certificate with a short field ID.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The byte buffer value to encode as this field.
 * \param size              The size of this field in bytes.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_BUILDER_ADD_INVALID_ARG if one of the arguments to
 *              this method is invalid.
 */
int vccert_builder_add_short_buffer(
    vccert_builder_context_t* context, uint16_t field, const uint8_t* value,
    size_t size)
{
    size_t field_size = FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + size;

    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->buffer.data != NULL);
    MODEL_ASSERT(context->offset + field_size <= context->buffer.size);
    MODEL_ASSERT(field_size <= VCCERT_MAX_FIELD_SIZE);

    /* verify that the parameters are valid. */
    if (context == NULL || context->buffer.data == NULL
     || context->buffer.size < context->offset + field_size)
    {
        return VCCERT_ERROR_BUILDER_ADD_INVALID_ARG;
    }

    /* verify that the field does not exceed the max supported field size. */
    if (field_size > VCCERT_MAX_FIELD_SIZE)
    {
        return VCCERT_ERROR_BUILDER_ADD_TOO_BIG;
    }

    /* write field header. */
    vccert_builder_write_fieldheader(context, field, size);

    /* write the value to the buffer. */
    uint8_t* out = ((uint8_t*)context->buffer.data) + context->offset;
    memcpy(out, value, size);

    /* increment the offset. */
    context->offset += size;

    return VCCERT_STATUS_SUCCESS;
}
