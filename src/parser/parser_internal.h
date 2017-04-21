/**
 * \file parser_internal.h
 *
 * Internal helper methods for parsing certificates.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_PRIVATE_PARSER_INTERNAL_HEADER_GUARD
#define VCCERT_PRIVATE_PARSER_INTERNAL_HEADER_GUARD

#include <vccert/parser.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

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
    size_t* next_offset);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_PRIVATE_PARSER_INTERNAL_HEADER_GUARD
