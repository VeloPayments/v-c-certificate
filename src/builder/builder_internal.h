/**
 * \file builder_internal.h
 *
 * Internal helper methods for building certificates.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_PRIVATE_BUILDER_INTERNAL_HEADER_GUARD
#define VCCERT_PRIVATE_BUILDER_INTERNAL_HEADER_GUARD

#include <vccert/builder.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**
 * Write a field header to a certificate and increment the offset.
 *
 * \param context           The builder context.
 * \param field_type        The 16-bit short field type for this field.
 * \param field_size        The size of the field value in bytes.
 */
void vccert_builder_write_fieldheader(
    vccert_builder_context_t* context, uint16_t field_type,
    size_t field_size);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_PRIVATE_BUILDER_INTERNAL_HEADER_GUARD
