/**
 * \file vccert_builder_add_short_int16.c
 *
 * Add an int16_t field to a certificate.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "builder_internal.h"

/**
 * \brief Add an int16_t field to the certificate with a short field ID.
 *
 * Note that this value will be written as a Big Endian integer value.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The uint16_t value to encode as this field.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_BUILDER_ADD_INVALID_ARG if one of the arguments to
 *              this method is invalid.
 */
int vccert_builder_add_short_int16(
    vccert_builder_context_t* context, uint16_t field, int16_t value)
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
    out[0] = (uint8_t)((value & 0xFF00) >> 8);
    out[1] = (uint8_t)((value & 0x00FF));

    //increment the offset
    context->offset += sizeof(value);

    return VCCERT_STATUS_SUCCESS;
}
