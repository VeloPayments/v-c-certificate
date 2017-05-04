/**
 * \file vccert_builder_add_short_UUID.c
 *
 * Add a UUID field to a certificate.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vpr/parameters.h>

#include "builder_internal.h"

/**
 * Add a UUID field to the certificate with a short field ID.
 *
 * Note that this value is expected as a Big Endian representation of a UUID.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The 128-bit UUID.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_add_short_UUID(
    vccert_builder_context_t* context, uint16_t field,
    const uint8_t* value)
{
    return vccert_builder_add_short_buffer(context, field, value, 16);
}
