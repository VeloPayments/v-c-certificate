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
 * \param height            The current height of the blockchani.
 * \param verifyContract    Set to true if the contract for the given
 *                          transaction should be verified.
 *
 * \returns 0 on success and non-zero on failure.
 */
int vccert_parser_attest(
    vccert_parser_context_t* context, uint64_t height, bool verifyContract)
{
    int retval = 1;

    MODEL_ASSERT(context != NULL);
    MODEL_ASSERT(context->options != NULL);
    MODEL_ASSERT(context->options->alloc_opts != NULL);
    MODEL_ASSERT(context->options->crypto_suite != NULL);
    MODEL_ASSERT(context->options->parser_options_transaction_resolver != NULL);
    MODEL_ASSERT(
        context->options->parser_options_artifact_state_resolver != NULL);
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

    /* Allocate a buffer for the signing entity's public signing key. */
    vccrypt_buffer_t public_key_buffer;
    if (0 !=
        vccrypt_suite_buffer_init_for_signature_public_key(
            context->options->crypto_suite, &public_key_buffer))
    {
        return PARSER_ATTEST_ERROR_GENERAL;
    }

    /* Allocate a buffer for the signing entity's public encryption key.  */
    vccrypt_buffer_t public_enc_key_buffer;
    if (0 !=
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            context->options->crypto_suite, &public_enc_key_buffer))
    {
        retval = PARSER_ATTEST_ERROR_GENERAL;
        goto public_key_buffer_dispose;
    }

    /* If we get to this point, we need the public signing key for the signer.
     * Request this from the caller by using the entity key resolver callback.
     */
    if (!context->options->parser_options_entity_key_resolver(
            context->options, context, height, signer_uuid,
            &public_enc_key_buffer, &public_key_buffer))
    {
        retval = PARSER_ATTEST_ERROR_MISSING_SIGNING_CERT;
        goto public_enc_key_buffer_dispose;
    }

    /* We can now compute the signature of the child certificate and verify that
     * it matches the signature field.
     */

    /* Create a buffer for the signature. */
    vccrypt_buffer_t signature_buffer;
    if (0 !=
        vccrypt_suite_buffer_init_for_signature(
            context->options->crypto_suite, &signature_buffer))
    {
        retval = PARSER_ATTEST_ERROR_GENERAL;
        goto public_enc_key_buffer_dispose;
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

    /* Adjust the size to include only what has been verified through
     * attestation.  Any fields past this point are outside of the signature and
     * cannot be trusted. An attacker can't append values to the end of an
     * otherwise valid certificate and fool the parser into trusting them. */
    context->size = (signature - context->cert) -
        FIELD_TYPE_SIZE - FIELD_SIZE_SIZE;

    /* short circuit if contract verification is not required */
    if (!verifyContract)
    {
        retval = PARSER_ATTEST_SUCCESS;
        goto sign_dispose;
    }

    /* get the transaction type id */
    const uint8_t* txn_type;
    size_t txn_type_size;
    if (0 !=
            vccert_parser_find_short(
                context, VCCERT_FIELD_TYPE_TRANSACTION_TYPE, &txn_type,
                &txn_type_size) ||
        16 != txn_type_size)
    {
        retval = PARSER_ATTEST_ERROR_MISSING_TRANSACTION_TYPE;
        goto sign_dispose;
    }

    /* get the artifact id */
    const uint8_t* artifact_id;
    size_t artifact_id_size;
    if (0 !=
            vccert_parser_find_short(
                context, VCCERT_FIELD_TYPE_TRANSACTION_TYPE, &artifact_id,
                &artifact_id_size) ||
        16 != artifact_id_size)
    {
        retval = PARSER_ATTEST_ERROR_MISSING_ARTIFACT_ID;
        goto sign_dispose;
    }

    /* lookup the contract function */
    vccert_contract_fn_t contract =
        context->options->parser_options_contract_resolver(
            context->options, context, txn_type, artifact_id);
    if (contract == NULL)
    {
        retval = PARSER_ATTEST_ERROR_MISSING_CONTRACT;
        goto sign_dispose;
    }

    /* execute the contract to verify this transaction. */
    if (!(*contract)(context->options, context))
    {
        retval = PARSER_ATTEST_ERROR_CONTRACT_VERIFICATION;
        goto sign_dispose;
    }

    /* At this point, the certificate chain has been attested. */
    retval = PARSER_ATTEST_SUCCESS;

sign_dispose:
    dispose((disposable_t*)&sign);

signature_buffer_dispose:
    dispose((disposable_t*)&signature_buffer);

public_enc_key_buffer_dispose:
    dispose((disposable_t*)&public_enc_key_buffer);

public_key_buffer_dispose:
    dispose((disposable_t*)&public_key_buffer);

    return retval;
}
