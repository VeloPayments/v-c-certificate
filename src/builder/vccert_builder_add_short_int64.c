/**
 * \file vccert_builder_add_short_int64.c
 *
 * Add an int64_t field to a certificate.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "builder_internal.h"

/**
 * Add an int64_t field to the certificate with a short field ID.
 *
 * Note that this value will be written as a Big Endian integer value.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The int64_t value to encode as this field.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_int64(
    vccert_builder_context_t* context, uint16_t field, int64_t value)
{
    size_t field_size = FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + sizeof(value);

    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->buffer.data != NULL);
    MODEL_ASSERT(context->offset + field_size <= context->buffer.size);

    if (context == NULL || context->buffer.data == NULL || context->buffer.size < context->offset + field_size)
    {
        return VCCERT_ERROR_BUILDER_ADD_INVALID_ARG;
    }

    //write field header
    vccert_builder_write_fieldheader(context, field, sizeof(value));

    //write the value to the buffer
    uint8_t* out = ((uint8_t*)context->buffer.data) + context->offset;
    out[0] = (uint8_t)((value & 0xFF00000000000000) >> 56);
    out[1] = (uint8_t)((value & 0x00FF000000000000) >> 48);
    out[2] = (uint8_t)((value & 0x0000FF0000000000) >> 40);
    out[3] = (uint8_t)((value & 0x000000FF00000000) >> 32);
    out[4] = (uint8_t)((value & 0x00000000FF000000) >> 24);
    out[5] = (uint8_t)((value & 0x0000000000FF0000) >> 16);
    out[6] = (uint8_t)((value & 0x000000000000FF00) >> 8);
    out[7] = (uint8_t)((value & 0x00000000000000FF));

    //increment the offset
    context->offset += sizeof(value);

    return VCCERT_STATUS_SUCCESS;
}
