/**
 * \file vccert_parser_find_short.c
 *
 * Find the first occurrence of a field in a certificate matching the given
 * short-hand identifier.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vpr/parameters.h>

#include "parser_internal.h"

/**
 * \brief Attempt to find the first occurrence of a field with the given
 * short-hand identifier in the certificate.
 *
 * If the certificate has not been attested, then this performs an UNSAFE SEARCH
 * of the RAW CERTIFICATE.  Run vccert_parser_attest() first if you want trusted
 * information.  Additional matching fields can be found by calling
 * vccert_parser_find_next().
 *
 * \param context           The parser context structure for this certificate.
 * \param field_id          The short-hand field identifier to find.
 * \param value             A pointer to the pointer to receive the value if the
 *                          field is found.
 * \param size              A pointer to receive the field size if the field is
 *                          found.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_NEXT_INVALID_FIELD_SIZE if a field with
 *        an invalid size is encountered in this certificate.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_NEXT_FIELD_NOT_FOUND if another field
 *        is not found.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_ARG if an invalid argument is
 *        provided.
 *      - \ref VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE if a field with an
 *        invalid size is encountered in the certificate.
 *      - a non-zero error code on failure.
 */
int vccert_parser_find_short(
    vccert_parser_context_t* context, uint16_t field_id,
    const uint8_t** value, size_t* size)
{
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->cert != NULL);
    MODEL_ASSERT(context->size > 0);
    MODEL_ASSERT(value != NULL);
    MODEL_ASSERT(size != NULL);

    uint16_t found_id = 0;
    size_t offset = 0;
    int retval = 0;

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
    if (retval != 0 || found_id != field_id)
    {
        *size = 0;
        *value = NULL;
        retval = 1;
    }

    return retval;
}
