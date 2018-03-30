/**
 * \file vccert_builder_sign.c
 *
 * Sign a certificate using a private key and add this signature to the end of
 * the certificate.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccert/fields.h>
#include <vpr/parameters.h>

#include "builder_internal.h"

/**
 * Sign the certificate using the given signer UUID and private key.
 *
 * Note that the signer_id is expected as a Big Endian representation of a UUID.
 *
 * \param context           The builder context to use for this operation.
 * \param signer_id         The 128-bit signer UUID.
 * \param private_key       The private key buffer to use to sign the
 *                          certificate.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_builder_sign(
    vccert_builder_context_t* context, const uint8_t* signer_id,
    const vccrypt_buffer_t* private_key)
{
    int retval = VCCERT_STATUS_SUCCESS;

    /* parameter sanity check */
    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(context->options->crypto_suite != NULL);
    MODEL_ASSERT(context->buffer.data != NULL);
    if (context == NULL || context->options == NULL || context->options->crypto_suite == NULL || context->buffer.data == NULL)
    {
        return VCCERT_ERROR_BUILDER_SIGN_INVALID_ARG;
    }

    /* buffer size check */
    size_t field_size =
        FIELD_TYPE_SIZE * 2 + FIELD_SIZE_SIZE * 2 + 16 +
        context->options->crypto_suite->sign_opts.signature_size;
    MODEL_ASSERT(context->buffer.size >= context->offset + field_size);
    if (context->buffer.size < context->offset + field_size)
    {
        return VCCERT_ERROR_BUILDER_SIGN_INVALID_FIELD_SIZE;
    }

    /* write the signer ID */
    retval = vccert_builder_add_short_UUID(
        context, VCCERT_FIELD_TYPE_SIGNER_ID, signer_id);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        return retval;
    }

    /* create a buffer for the signature */
    vccrypt_buffer_t signature;
    retval = vccrypt_suite_buffer_init_for_signature(
        context->options->crypto_suite, &signature);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        return retval;
    }

    /* write signature field header */
    vccert_builder_write_fieldheader(
        context, VCCERT_FIELD_TYPE_SIGNATURE, signature.size);

    /* create the digital signature context */
    vccrypt_digital_signature_context_t sign;
    retval = vccrypt_suite_digital_signature_init(
        context->options->crypto_suite, &sign);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        goto dispose_signature;
    }

    /* sign the certificate */
    retval = vccrypt_digital_signature_sign(
        &sign, &signature, private_key,
        (const uint8_t*)context->buffer.data, context->offset);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        goto dispose_sign_context;
    }

    /* write the signature to the buffer */
    uint8_t* out = ((uint8_t*)context->buffer.data) + context->offset;
    memcpy(out, signature.data, signature.size);

    /* increment the offset */
    context->offset += signature.size;

    retval = VCCERT_STATUS_SUCCESS;

dispose_sign_context:
    dispose((disposable_t*)&sign);

dispose_signature:
    dispose((disposable_t*)&signature);

    return retval;
}
