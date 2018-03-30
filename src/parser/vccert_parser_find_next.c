/**
 * \file vccert_parser_find_next.c
 *
 * Find the next occurrence of a field in a certificate matching the given
 * short-hand identifier of the current field.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vpr/parameters.h>

#include "parser_internal.h"

/**
 * Attempt to find the next occurrence of a field with the same short-hand
 * identifier as the current field in the certificate. If the certificate has
 * not been attested, then this performs an UNSAFE SEARCH of the RAW
 * CERTIFICATE.  Run vccert_parser_attest() first if you want trusted
 * information.
 *
 * \param context           The parser context structure for this certificate.
 * \param value             A pointer to the pointer of the current field.  This
 *                          will be updated with the next field with the same
 *                          field type ID.
 * \param size              A pointer to receive the field size if the field is
 *                          found.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_parser_find_next(
    vccert_parser_context_t* context, const uint8_t** value, size_t* size)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->cert != NULL);
    MODEL_ASSERT(context->size > 0);
    MODEL_ASSERT(value != NULL);
    MODEL_ASSERT(*value != NULL);
    MODEL_ASSERT(size != NULL);

    uint16_t field_id = 0;
    uint16_t found_id = 0;
    int retval = 0;

    /* do some math to get to the beginning of the current field */
    size_t offset =
        (*value - context->cert) - (FIELD_TYPE_SIZE + FIELD_SIZE_SIZE);
    if (offset > context->size)
    {
        return VCCERT_ERROR_PARSER_FIND_NEXT_INVALID_FIELD_SIZE;
    }

    /* get the next field offset */
    if (VCCERT_STATUS_SUCCESS !=
        vccert_parser_field(context->cert, context->size, offset, &field_id,
            size, value, &offset))
    {
        return VCCERT_ERROR_PARSER_FIND_NEXT_FIELD_NOT_FOUND;
    }

    /* search through all fields for a matching occurrence. */
    do
    {
        retval =
            vccert_parser_field(context->cert, context->size, offset, &found_id,
                size, value, &offset);

        if (found_id == field_id)
            break;

    } while (retval == VCCERT_STATUS_SUCCESS);

    /* did we find a valid field? */
    if (retval != VCCERT_STATUS_SUCCESS || found_id != field_id)
    {
        *size = 0;
        *value = NULL;
        retval = VCCERT_ERROR_PARSER_FIND_NEXT_FIELD_NOT_FOUND;
    }

    return retval;
}
