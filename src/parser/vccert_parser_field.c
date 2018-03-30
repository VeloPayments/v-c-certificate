/**
 * \file vccert_parser_field.c
 *
 * Parse the current certificate field and return the offset to the next
 * certificate field.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vpr/parameters.h>

#include "parser_internal.h"

/**
 * Parse a certificate field, and return the offset to the next field in this
 * certificate.
 *
 * \param cert              A pointer to the raw certificate.
 * \param size              The size of the raw certificate.
 * \param offset            The current field offset.
 * \param field_type        A pointer to receive the short-hand field type for
 *                          this field.
 * \param field_size        A pointer to receive the field size for this field.
 * \param field             A pointer to receive the raw field data.
 * \param next_offset       A pointer to receive the next field offset.  Note
 *                          that this offset will be set to a value greater than
 *                          the raw certificate size if no next field exists.
 *
 * \returns 0 if the field could be parsed, and non-zero otherwise.
 */
int vccert_parser_field(
    const uint8_t* cert, size_t size, size_t offset,
    uint16_t* field_type, size_t* field_size, const uint8_t** field,
    size_t* next_offset)
{
    MODEL_ASSERT(cert != NULL);
    MODEL_ASSERT(size > 0);
    MODEL_ASSERT(offset < size);
    MODEL_ASSERT(offset + FIELD_TYPE_SIZE + FIELD_SIZE_SIZE < size);
    MODEL_ASSERT(field_type != NULL);
    MODEL_ASSERT(field_size != NULL);
    MODEL_ASSERT(field != NULL);
    MODEL_ASSERT(next_offset != NULL);

    /* parameter sanity checks */
    if (
        cert == NULL /* null check */
        || size == 0 /* size sanity */
        || offset + FIELD_TYPE_SIZE + FIELD_SIZE_SIZE >= size /* field sanity */
        || field_type == NULL /* output sanity */
        || field_size == NULL /* output sanity */
        || field == NULL /* output sanity */
        || next_offset == NULL) /* output sanity */
    {
        return VCCERT_ERROR_PARSER_FIELD_INVALID_ARG;
    }

    /* the field type is a big-Endian 16-bit number */
    *field_type = (((uint16_t)cert[offset + 0]) << 8) | cert[offset + 1];

    /* the field size is a big-Endian 16-bit number */
    *field_size = (((uint16_t)cert[offset + 2]) << 8) | cert[offset + 3];

    /* sanity check the field size */
    if (offset + FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + *field_size > size)
    {
        /* nonsense size.  We can't have a field that extends past the end of
         * the certificate.
         */
        return VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE;
    }

    /* the field value starts immediately after the field type and field size
       fields */
    *field = cert + offset + FIELD_TYPE_SIZE + FIELD_SIZE_SIZE;

    /* the next field starts immediately after the end of the field
     * Since field_size is a uint16_t value, the following math is valid as long
     * as sizeof(uint16_t) < sizeof(size_t).  Since we treat field_size as an
     * unsigned value, then next_offset must be between offset + 4 and offset +
     * 65539 inclusive.  If this exceeds the end of the certificate, then we've
     * reached the end.
     */
    MODEL_ASSERT(sizeof(uint16_t) < sizeof(size_t));
    *next_offset = offset + FIELD_TYPE_SIZE + FIELD_SIZE_SIZE + *field_size;

    /* success */
    return VCCERT_STATUS_SUCCESS;
}
