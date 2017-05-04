/**
 * \file vccert_builder_write_fieldheader.c
 *
 * Write a field header to the certificate builder and update the offset.
 * Private method.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccert/builder.h>
#include <vpr/parameters.h>

/**
 * Write a field header to a certificate and increment the offset.
 *
 * \param context           The builder context.
 * \param field_type        The 16-bit short field type for this field.
 * \param field_size        The size of the field value in bytes.
 */
void vccert_builder_write_fieldheader(
    vccert_builder_context_t* context, uint16_t field_type,
    size_t field_size)
{
    size_t header_size = FIELD_TYPE_SIZE + FIELD_SIZE_SIZE;

    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->builder.data != NULL);
    MODEL_ASSERT(context->offset + header_size <= context->builder.size);
    MODEL_ASSERT(field_size >= 0 && field_size <= 0xFFFF);
    MODEL_ASSERT(header_size == 4);

    uint8_t* out = ((uint8_t*)context->buffer.data) + context->offset;

    //write the field type as an unsigned 16-bit Big Endian value.
    out[0] = (uint8_t)((field_type & 0xFF00) >> 8);
    out[1] = (uint8_t)((field_type & 0x00FF));

    //write the field size as an unsigned 16-bit Big Endian value.
    out[2] = (uint8_t)((field_size & 0xFF00) >> 8);
    out[3] = (uint8_t)((field_size & 0x00FF));

    //increment the offset
    context->offset += header_size;
}
