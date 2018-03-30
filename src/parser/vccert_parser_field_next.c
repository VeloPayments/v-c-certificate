/**
 * \file vccert_parser_field_next.c
 *
 * Return the next field in the certificate, after this given field.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vpr/parameters.h>

#include "parser_internal.h"

/**
 * Return the next field in the certificate.  If the certificate has not been
 * attested, then this performs an UNSAFE SEARCH of the RAW CERTIFICATE.  Run
 * vccert_parser_attest() first if you want trusted information.  Additional
 * fields can be found by calling vccert_parser_field_next().  The value pointer
 * should be pointing to a valid field in this certificate.  It will be used to
 * compute the offset of the next field in the certificate.
 *
 * \param context           The parser context structure for this certificate.
 * \param field_id          The pointer to receive the short-hand field
 *                          identifier.
 * \param value             The pointer to receive a pointer to the field value.
 *                          This pointer should be set to a valid field value in
 *                          the certificate.
 * \param size              The pointer to receive the size of this field.
 *
 * \returns 0 on success and non-zero if no fields exist in this certificate.
 */
int vccert_parser_field_next(
    vccert_parser_context_t* context, uint16_t* field_id,
    const uint8_t** value, size_t* size)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->cert != NULL);
    MODEL_ASSERT(context->size > 0);
    MODEL_ASSERT(field_id != NULL);
    MODEL_ASSERT(value != NULL);
    MODEL_ASSERT(*value != NULL);
    MODEL_ASSERT(*value > context->cert);
    MODEL_ASSERT(context->cert + context->size > *value);
    MODEL_ASSERT(size != NULL);

    /* do some math to get to the beginning of the current field */
    size_t offset =
        (*value - context->cert) - (FIELD_TYPE_SIZE + FIELD_SIZE_SIZE);
    if (offset > context->size)
    {
        return VCCERT_ERROR_PARSER_FIELD_NEXT_INVALID_FIELD_SIZE;
    }

    /* get the next field offset */
    if (VCCERT_STATUS_SUCCESS !=
        vccert_parser_field(context->cert, context->size, offset, field_id,
            size, value, &offset))
    {
        return VCCERT_ERROR_PARSER_FIELD_NEXT_FIELD_NOT_FOUND;
    }

    /* parse the next field */
    return vccert_parser_field(context->cert, context->size, offset, field_id,
        size, value, &offset);
}
