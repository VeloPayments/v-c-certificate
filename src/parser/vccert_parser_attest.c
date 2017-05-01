/**
 * \file vccert_parser_attest.c
 *
 * Perform attestation on a certificate / certificate chain to verify the
 * provenance of a certificate and verify any contracts on this certificate.
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccert/fields.h>
#include <vccert/parser.h>
#include <vccrypt/compare.h>
#include <vpr/parameters.h>

/**
 * Perform attestation on a certificate.
 *
 * \param context           The parser context structure holding the certificate
 *                          on which attestation should be performed.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_parser_attest(vccert_parser_context_t* context)
{
    int retval = 1;

    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(context->options->alloc_opts != NULL);
    MODEL_ASSERT(context->options->crypto_suite != NULL);
    MODEL_ASSERT(context->options->parser_options_entity_resolver != NULL);
    MODEL_ASSERT(
        context->options->parser_options_entity_state_resolver != NULL);
    MODEL_ASSERT(context->options->parser_options_contract_resolver != NULL);

    /* Attestation uses the raw size of the certificate.  In case attestation
     * was performed previously, we need to force the size of the certificate to
     * be equal to the raw size.
     */
    context->size = context->raw_size;

    /* First, we need to get the UUID of the signer. */
    const uint8_t* signer_uuid;
    size_t signer_uuid_size;
    if (0 !=
            vccert_parser_find_short(
                context, VCCERT_FIELD_TYPE_SIGNER_ID, &signer_uuid,
                &signer_uuid_size) ||
        16 != signer_uuid_size)
    {
        return PARSER_ATTEST_ERROR_MISSING_SIGNER_UUID;
    }

    /* Now, we need the signature. */
    const uint8_t* signature;
    size_t signature_size;
    if (0 !=
            vccert_parser_find_short(
                context, VCCERT_FIELD_TYPE_SIGNATURE, &signature, &signature_size) ||
        context->options->crypto_suite->sign_opts.signature_size != signature_size)
    {
        return PARSER_ATTEST_ERROR_MISSING_SIGNATURE;
    }

    /* If we get to this point, we need the public signing key for the signer.
     * Request this from the caller by using the entity resolver callback.
     */
    bool can_trust = false;
    if (!context->options->parser_options_entity_resolver(
            context->options, context, signer_uuid, &context->parent_buffer,
            &can_trust))
    {
        return PARSER_ATTEST_ERROR_MISSING_SIGNING_CERT;
    }

    /* allocate memory for the parent certificate parser context */
    context->parent =
        (vccert_parser_context_t*)allocate(
            context->options->alloc_opts, sizeof(vccert_parser_context_t));
    if (!context->parent)
    {
        retval = PARSER_ATTEST_ERROR_GENERAL;
        goto buffer_dispose;
    }

    /* initialize the parent certificate parser */
    if (0 !=
        vccert_parser_init(
            context->options, context->parent,
            context->parent_buffer.data, context->parent_buffer.size))
    {
        retval = PARSER_ATTEST_ERROR_GENERAL;
        goto parent_release;
    }

    /* if the certificate isn't trusted, then we must recursively attest it
     * before continuing.
     */
    if (!can_trust)
    {
        /* perform attestation on this certificate */
        if (0 != vccert_parser_attest(context->parent))
        {
            retval = PARSER_ATTEST_ERROR_CHAIN_ATTESTATION;
            goto parent_dispose;
        }
    }

    /* at this point, we can trust the parent certificate.  Verify that the
     * entity UUID matches the signer UUID.
     */
    const uint8_t* parent_entity_uuid;
    size_t parent_entity_uuid_size;
    if (0 !=
            vccert_parser_find_short(
                context->parent, VCCERT_FIELD_TYPE_ARTIFACT_ID, &parent_entity_uuid,
                &parent_entity_uuid_size) ||
        16 != parent_entity_uuid_size)
    {
        retval = PARSER_ATTEST_ERROR_SIGNER_UUID_MISMATCH;
        goto parent_dispose;
    }

    /* The parent artifact ID should match the signer ID. */
    if (0 != crypto_memcmp(signer_uuid, parent_entity_uuid, signer_uuid_size))
    {
        retval = PARSER_ATTEST_ERROR_SIGNER_UUID_MISMATCH;
        goto parent_dispose;
    }

    /* Get the parent public signing key. */
    const uint8_t* parent_public_signing_key;
    size_t parent_public_signing_key_size;
    if (0 !=
            vccert_parser_find_short(
                context->parent, VCCERT_FIELD_TYPE_PUBLIC_SIGNING_KEY,
                &parent_public_signing_key, &parent_public_signing_key_size) ||
        context->options->crypto_suite->sign_opts.public_key_size != parent_public_signing_key_size)
    {
        retval = PARSER_ATTEST_ERROR_SIGNER_MISSING_SIGNING_KEY;
        goto parent_dispose;
    }

    /* We can now compute the signature of the child certificate and verify that
     * it matches the signature field.
     */

    /* Create a buffer for the public signing key. */
    vccrypt_buffer_t public_key_buffer;
    if (0 !=
        vccrypt_suite_buffer_init_for_signature_public_key(
            context->options->crypto_suite, &public_key_buffer))
    {
        retval = PARSER_ATTEST_ERROR_GENERAL;
        goto parent_dispose;
    }
    memcpy(public_key_buffer.data, parent_public_signing_key,
        public_key_buffer.size);

    /* Create a buffer for the signature. */
    vccrypt_buffer_t signature_buffer;
    if (0 !=
        vccrypt_suite_buffer_init_for_signature(
            context->options->crypto_suite, &signature_buffer))
    {
        retval = PARSER_ATTEST_ERROR_GENERAL;
        goto public_key_buffer_dispose;
    }
    memcpy(signature_buffer.data, signature, signature_buffer.size);

    /* Create a digital signature context */
    vccrypt_digital_signature_context_t sign;
    if (0 !=
        vccrypt_suite_digital_signature_init(
            context->options->crypto_suite, &sign))
    {
        retval = PARSER_ATTEST_ERROR_GENERAL;
        goto signature_buffer_dispose;
    }

    /* verify the signature for this certificate */
    if (0 !=
        vccrypt_digital_signature_verify(
            &sign, &signature_buffer, &public_key_buffer, context->cert,
            signature - context->cert))
    {
        retval = PARSER_ATTEST_ERROR_SIGNATURE_MISMATCH;
        goto sign_dispose;
    }

    /* TODO - add smart contract capability */

    /* Adjust the size to include only what has been verified through
     * attestation.  Any fields past this point are outside of the signature and
     * cannot be trusted. An attacker can't append values to the end of an
     * otherwise valid certificate and fool the parser into trusting them. */
    context->size = (signature - context->cert) -
        FIELD_TYPE_SIZE - FIELD_SIZE_SIZE;

    /* At this point, the certificate chain has been attested. */
    retval = 0;

sign_dispose:
    dispose((disposable_t*)&sign);

signature_buffer_dispose:
    dispose((disposable_t*)&signature_buffer);

public_key_buffer_dispose:
    dispose((disposable_t*)&public_key_buffer);

parent_dispose:
    if (context->parent)
        dispose((disposable_t*)context->parent);

parent_release:
    if (context->parent)
        release(context->options->alloc_opts, context->parent);
    context->parent = NULL;

buffer_dispose:
    dispose((disposable_t*)&context->parent_buffer);
    context->parent_buffer.data = NULL;
    context->parent_buffer.size = 0;

    return retval;
}
