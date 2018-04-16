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
 * \brief Add a UUID field to the certificate with a short field ID.
 *
 * Note that this value is expected as a Big Endian representation of a UUID.
 *
 * \param context           The builder context to use for this operation.
 * \param field             The short field ID to add.
 * \param value             The 128-bit UUID.
 *
 * \returns a status code indicating success or failure.
 *      - \ref VCCERT_STATUS_SUCCESS on success.
 *      - \ref VCCERT_ERROR_BUILDER_ADD_INVALID_ARG if one of the arguments to
 *              this method is invalid.
 */
int vccert_builder_add_short_UUID(
    vccert_builder_context_t* context, uint16_t field,
    const uint8_t* value)
{
    return vccert_builder_add_short_buffer(context, field, value, 16);
}
