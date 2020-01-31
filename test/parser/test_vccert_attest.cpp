/**
 * \file test_vccert_attest.cpp
 *
 * Test vccert_attest.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <vccert/builder.h>
#include <vccert/fields.h>
#include <vccert/parser.h>
#include <vccrypt/suite.h>
#include <vpr/allocator/malloc_allocator.h>

//forward declarations for dummy certificate delegate methods
static bool dummy_txn_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccrypt_buffer_t*, bool*);
static int32_t dummy_artifact_state_resolver(
    void*, void*, const uint8_t*, vccrypt_buffer_t*);
static bool dummy_entity_key_resolver(
    void*, void*, uint64_t, const uint8_t*, vccrypt_buffer_t*,
    vccrypt_buffer_t*);
static int dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccert_contract_closure_t* closure);
static int fail_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccert_contract_closure_t* closure);

static int create_signed_certificate(
    bool enable_field_skip,
    int skip_field,
    uint8_t** cert,
    size_t* cert_size);

static const uint8_t* PRIVATE_KEY = (const uint8_t*)"\x65\x93\x21\xd0\x35\xa9\xf8\xcf"
                                                    "\x35\x37\xd1\xd1\x82\xfd\xee\xf8"
                                                    "\x92\x8e\x0c\xfe\xb4\x56\x4b\x2d"
                                                    "\xb5\x11\x60\x6d\xc6\xf6\x13\xbd"
                                                    "\x47\x83\xe9\xf6\x78\xd1\x49\xac"
                                                    "\xd2\x09\x66\xb0\xab\x88\xf7\xd0"
                                                    "\x5d\x6d\x4f\x54\x0f\x1f\x23\x82"
                                                    "\x86\x00\x3a\xda\x0c\x27\xcc\x35";

static const uint8_t* SIGNER_ID = (const uint8_t*)"\x71\x1f\x22\x65\xb6\x50\x46\x12"
                                                  "\xa7\x3a\xad\x82\x7f\xb2\x71\x18";

static const uint8_t* TEST_CERT = (const uint8_t*)
    //certificate version
    "\x00\x01\x00\x04\x00\x01\x00\x00"
    //certificate valid from / transaction date
    "\x00\x10\x00\x08\x00\x00\x00\x00\x5a\x5c\x23\x72"
    //certificate crypto suite
    "\x00\x20\x00\x02\x00\x01"
    //certificate type
    "\x00\x30\x00\x10"
    "\x52\xa7\xf0\xfb\x8a\x6b\x4d\x03\x86\xa5\x7f\x61\x2f\xcf\x7e\xff"
    //certificate id / transaction id
    "\x00\x38\x00\x10"
    "\x1d\x6e\x32\xfa\x1f\x23\x49\xf4\xa5\xaa\x57\x05\x48\x93\xc5\xf6"
    //previous certificate id / transaction id
    "\x00\x39\x00\x10"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    //transaction type
    "\x00\x76\x00\x10"
    "\x17\xe1\xfc\x1f\x5d\xd9\x44\xa9\xb4\x9d\x1b\x6c\x1e\xb6\xd0\x11"
    //artifact type
    "\x00\x40\x00\x10"
    "\x6d\x34\x1a\x9b\x42\xaf\x45\x3d\xac\xdb\x4a\x99\x63\xd9\xd1\x4e"
    //artifact id
    "\x00\x41\x00\x10"
    "\x3e\xe2\x99\x7b\x2d\x4f\x48\x2e\x86\x58\x88\x86\x06\xd1\x35\x03"
    //previous artifact state
    "\x00\x42\x00\x02\x00\x02"
    //new artifact state
    "\x00\x43\x00\x02\x00\x03"
    //signer id
    "\x00\x50\x00\x10"
    "\x71\x1f\x22\x65\xb6\x50\x46\x12\xa7\x3a\xad\x82\x7f\xb2\x71\x18"
    //signature
    "\x00\x51\x00\x40"
    "\x31\xf9\xc2\x79\x3a\x92\xa6\x9c\x61\xf4\x95\x87\xb6\xfe\x53\x03"
    "\x33\x54\x93\x1d\x9b\xca\xb2\x92\x58\x8f\x97\xdd\xdc\xb1\x35\xab"
    "\xc9\xeb\xc2\x99\x9a\x69\x3f\x9b\x9d\xa3\x5c\xec\x4a\x82\x10\x6e"
    "\xab\x06\x26\xe5\xc2\x1b\xa5\x0e\x0b\x2d\xfb\x26\xe1\xef\x93\x03";

static const size_t TEST_CERT_SIZE = 246;

static const uint8_t* SIGNING_KEY = (const uint8_t*)"\x47\x83\xe9\xf6\x78\xd1\x49\xac"
                                                    "\xd2\x09\x66\xb0\xab\x88\xf7\xd0"
                                                    "\x5d\x6d\x4f\x54\x0f\x1f\x23\x82"
                                                    "\x86\x00\x3a\xda\x0c\x27\xcc\x35";

static const uint8_t* NULL_KEY = (const uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00"
                                                 "\x00\x00\x00\x00\x00\x00\x00\x00"
                                                 "\x00\x00\x00\x00\x00\x00\x00\x00"
                                                 "\x00\x00\x00\x00\x00\x00\x00\x00";

class vccert_parser_attest_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        vccrypt_suite_register_velo_v1();

        malloc_allocator_options_init(&alloc_opts);

        suite_init_result =
            vccrypt_suite_options_init(&crypto_suite, &alloc_opts,
                VCCRYPT_SUITE_VELO_V1);

        options_init_result =
            vccert_parser_options_init(
                &options, &alloc_opts, &crypto_suite, &dummy_txn_resolver,
                &dummy_artifact_state_resolver, &dummy_contract_resolver,
                &dummy_entity_key_resolver, &dummy_context);

        parser_init_result =
            vccert_parser_init(&options, &parser, TEST_CERT, TEST_CERT_SIZE);
    }

    void TearDown() override
    {
        if (options_init_result == 0)
        {
            dispose((disposable_t*)&options);
        }

        if (suite_init_result == 0)
        {
            dispose((disposable_t*)&crypto_suite);
        }

        if (parser_init_result == 0)
        {
            dispose((disposable_t*)&parser);
        }

        dispose((disposable_t*)&alloc_opts);
    }

    int suite_init_result, options_init_result, parser_init_result;
    int dummy_context;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t crypto_suite;
    vccert_parser_options_t options;
    vccert_parser_context_t parser;
};

/**
 * Sanity test of external dependencies.
 */
TEST_F(vccert_parser_attest_test, external_dependencies)
{
    ASSERT_EQ(0, options_init_result);
    ASSERT_EQ(0, suite_init_result);
    ASSERT_EQ(0, parser_init_result);
}

/**
 * Simple happy path attestation.
 */
TEST_F(vccert_parser_attest_test, happy_path)
{
    //the size and raw size should be the same
    ASSERT_EQ(TEST_CERT_SIZE, parser.raw_size);
    ASSERT_EQ(TEST_CERT_SIZE, parser.size);

    //attestation should succeed
    ASSERT_EQ(0, vccert_parser_attest(&parser, 77, true));

    //the new size should exclude the signature field.
    ASSERT_EQ(TEST_CERT_SIZE, parser.raw_size);
    ASSERT_EQ(TEST_CERT_SIZE - 68, parser.size);
}

/**
 * Demonstrate that contract validation can be bypassed.
 */
TEST_F(vccert_parser_attest_test, bypass_contract)
{
    //the size and raw size should be the same
    ASSERT_EQ(TEST_CERT_SIZE, parser.raw_size);
    ASSERT_EQ(TEST_CERT_SIZE, parser.size);

    //switch contract resolver to something that always returns a fail contract.
    parser.options->parser_options_contract_resolver = &fail_contract_resolver;

    //attestation should succeed
    ASSERT_EQ(0, vccert_parser_attest(&parser, 77, false));

    //the new size should exclude the signature field.
    ASSERT_EQ(TEST_CERT_SIZE, parser.raw_size);
    ASSERT_EQ(TEST_CERT_SIZE - 68, parser.size);
}

/**
 * A certificate without a signer UUID fails attestation.
 */
TEST_F(vccert_parser_attest_test, missing_signer_id)
{
    vccert_parser_context_t failparser;

    const uint8_t FAIL_CERT[] = {
        /* certificate version */
        0x00, 0x01, 0x00, 0x04,
        0x00, 0x01, 0x00, 0x00,
        /* certificate valid from / transaction date */
        0x00, 0x10, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x5a, 0x5c, 0x23, 0x72,
        /* certificate crypto suite */
        0x00, 0x20, 0x00, 0x02,
        0x00, 0x01,
        /* certificate type */
        0x00, 0x30, 0x00, 0x10,
        0x52, 0xa7, 0xf0, 0xfb, 0x8a, 0x6b, 0x4d, 0x03, 0x86, 0xa5, 0x7f,
        0x61, 0x2f, 0xcf, 0x7e, 0xff,
        /* certificate id / transaction id */
        0x00, 0x38, 0x00, 0x10,
        0x1d, 0x6e, 0x32, 0xfa, 0x1f, 0x23, 0x49, 0xf4, 0xa5, 0xaa, 0x57,
        0x05, 0x48, 0x93, 0xc5, 0xf6,
        /* previous certificate id / transaction id */
        0x00, 0x39, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        /* transaction type */
        0x00, 0x76, 0x00, 0x10,
        0x17, 0xe1, 0xfc, 0x1f, 0x5d, 0xd9, 0x44, 0xa9, 0xb4, 0x9d, 0x1b,
        0x6c, 0x1e, 0xb6, 0xd0, 0x11,
        /* artifact type */
        0x00, 0x40, 0x00, 0x10,
        0x6d, 0x34, 0x1a, 0x9b, 0x42, 0xaf, 0x45, 0x3d, 0xac, 0xdb, 0x4a,
        0x99, 0x63, 0xd9, 0xd1, 0x4e,
        /* artifact id */
        0x00, 0x41, 0x00, 0x10,
        0x3e, 0xe2, 0x99, 0x7b, 0x2d, 0x4f, 0x48, 0x2e, 0x86, 0x58, 0x88,
        0x86, 0x06, 0xd1, 0x35, 0x03,
        /* previous artifact state */
        0x00, 0x42, 0x00, 0x02,
        0x00, 0x02,
        /* new artifact state */
        0x00, 0x43, 0x00, 0x02,
        0x00, 0x03
    };

    /* creating our fail parser should succeed. */
    ASSERT_EQ(VCCERT_STATUS_SUCCESS,
        vccert_parser_init(
            &options, &failparser, FAIL_CERT, sizeof(FAIL_CERT)));

    /* attestation should fail with
     * VCCERT_ERROR_PARSER_ATTEST_MISSING_SIGNER_UUID */
    EXPECT_EQ(VCCERT_ERROR_PARSER_ATTEST_MISSING_SIGNER_UUID,
        vccert_parser_attest(&failparser, 77, false));

    /* clean up. */
    dispose((disposable_t*)&failparser);
}

/**
 * A certificate without a signature fails attestation.
 */
TEST_F(vccert_parser_attest_test, missing_signature)
{
    vccert_parser_context_t failparser;

    const uint8_t FAIL_CERT[] = {
        /* certificate version */
        0x00, 0x01, 0x00, 0x04,
        0x00, 0x01, 0x00, 0x00,
        /* certificate valid from / transaction date */
        0x00, 0x10, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x5a, 0x5c, 0x23, 0x72,
        /* certificate crypto suite */
        0x00, 0x20, 0x00, 0x02,
        0x00, 0x01,
        /* certificate type */
        0x00, 0x30, 0x00, 0x10,
        0x52, 0xa7, 0xf0, 0xfb, 0x8a, 0x6b, 0x4d, 0x03, 0x86, 0xa5, 0x7f,
        0x61, 0x2f, 0xcf, 0x7e, 0xff,
        /* certificate id / transaction id */
        0x00, 0x38, 0x00, 0x10,
        0x1d, 0x6e, 0x32, 0xfa, 0x1f, 0x23, 0x49, 0xf4, 0xa5, 0xaa, 0x57,
        0x05, 0x48, 0x93, 0xc5, 0xf6,
        /* previous certificate id / transaction id */
        0x00, 0x39, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        /* transaction type */
        0x00, 0x76, 0x00, 0x10,
        0x17, 0xe1, 0xfc, 0x1f, 0x5d, 0xd9, 0x44, 0xa9, 0xb4, 0x9d, 0x1b,
        0x6c, 0x1e, 0xb6, 0xd0, 0x11,
        /* artifact type */
        0x00, 0x40, 0x00, 0x10,
        0x6d, 0x34, 0x1a, 0x9b, 0x42, 0xaf, 0x45, 0x3d, 0xac, 0xdb, 0x4a,
        0x99, 0x63, 0xd9, 0xd1, 0x4e,
        /* artifact id */
        0x00, 0x41, 0x00, 0x10,
        0x3e, 0xe2, 0x99, 0x7b, 0x2d, 0x4f, 0x48, 0x2e, 0x86, 0x58, 0x88,
        0x86, 0x06, 0xd1, 0x35, 0x03,
        /* previous artifact state */
        0x00, 0x42, 0x00, 0x02,
        0x00, 0x02,
        /* new artifact state */
        0x00, 0x43, 0x00, 0x02,
        0x00, 0x03,
        /* signer id */
        0x00, 0x50, 0x00, 0x10,
        0x71, 0x1f, 0x22, 0x65, 0xb6, 0x50, 0x46, 0x12, 0xa7, 0x3a, 0xad,
        0x82, 0x7f, 0xb2, 0x71, 0x18
    };

    /* creating our fail parser should succeed. */
    ASSERT_EQ(VCCERT_STATUS_SUCCESS,
        vccert_parser_init(
            &options, &failparser, FAIL_CERT, sizeof(FAIL_CERT)));

    /* attestation should fail with
     * VCCERT_ERROR_PARSER_ATTEST_MISSING_SIGNATURE */
    EXPECT_EQ(VCCERT_ERROR_PARSER_ATTEST_MISSING_SIGNATURE,
        vccert_parser_attest(&failparser, 77, false));

    /* clean up. */
    dispose((disposable_t*)&failparser);
}

/**
 * A certificate with a bad signature fails attestation.
 */
TEST_F(vccert_parser_attest_test, bad_signature)
{
    vccert_parser_context_t failparser;

    const uint8_t FAIL_CERT[] = {
        /* certificate version */
        0x00, 0x01, 0x00, 0x04,
        0x00, 0x01, 0x00, 0x00,
        /* certificate valid from / transaction date */
        0x00, 0x10, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x5a, 0x5c, 0x23, 0x72,
        /* certificate crypto suite */
        0x00, 0x20, 0x00, 0x02,
        0x00, 0x01,
        /* certificate type */
        0x00, 0x30, 0x00, 0x10,
        0x52, 0xa7, 0xf0, 0xfb, 0x8a, 0x6b, 0x4d, 0x03, 0x86, 0xa5, 0x7f,
        0x61, 0x2f, 0xcf, 0x7e, 0xff,
        /* certificate id / transaction id */
        0x00, 0x38, 0x00, 0x10,
        0x1d, 0x6e, 0x32, 0xfa, 0x1f, 0x23, 0x49, 0xf4, 0xa5, 0xaa, 0x57,
        0x05, 0x48, 0x93, 0xc5, 0xf6,
        /* previous certificate id / transaction id */
        0x00, 0x39, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        /* transaction type */
        0x00, 0x76, 0x00, 0x10,
        0x17, 0xe1, 0xfc, 0x1f, 0x5d, 0xd9, 0x44, 0xa9, 0xb4, 0x9d, 0x1b,
        0x6c, 0x1e, 0xb6, 0xd0, 0x11,
        /* artifact type */
        0x00, 0x40, 0x00, 0x10,
        0x6d, 0x34, 0x1a, 0x9b, 0x42, 0xaf, 0x45, 0x3d, 0xac, 0xdb, 0x4a,
        0x99, 0x63, 0xd9, 0xd1, 0x4e,
        /* artifact id */
        0x00, 0x41, 0x00, 0x10,
        0x3e, 0xe2, 0x99, 0x7b, 0x2d, 0x4f, 0x48, 0x2e, 0x86, 0x58, 0x88,
        0x86, 0x06, 0xd1, 0x35, 0x03,
        /* previous artifact state */
        0x00, 0x42, 0x00, 0x02,
        0x00, 0x02,
        /* new artifact state */
        0x00, 0x43, 0x00, 0x02,
        0x00, 0x03,
        /* signer id */
        0x00, 0x50, 0x00, 0x10,
        0x71, 0x1f, 0x22, 0x65, 0xb6, 0x50, 0x46, 0x12, 0xa7, 0x3a, 0xad,
        0x82, 0x7f, 0xb2, 0x71, 0x18,
        /* bad signature. */
        0x00, 0x51, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    /* creating our fail parser should succeed. */
    ASSERT_EQ(VCCERT_STATUS_SUCCESS,
        vccert_parser_init(
            &options, &failparser, FAIL_CERT, sizeof(FAIL_CERT)));

    /* attestation should fail with
     * VCCERT_ERROR_PARSER_ATTEST_SIGNATURE_MISMATCH */
    EXPECT_EQ(VCCERT_ERROR_PARSER_ATTEST_SIGNATURE_MISMATCH,
        vccert_parser_attest(&failparser, 77, false));

    /* clean up. */
    dispose((disposable_t*)&failparser);
}

/**
 * A certificate with a missing transaction type fails attestation, if
 * verifyContract is true.
 */
TEST_F(vccert_parser_attest_test, missing_transaction_type)
{
    vccert_parser_context_t failparser;

    uint8_t* FAIL_CERT = 0;
    size_t FAIL_CERT_SIZE = 0;

    /* we should be able to create a signed certificate. */
    ASSERT_EQ(VCCERT_STATUS_SUCCESS,
        create_signed_certificate(
            true, VCCERT_FIELD_TYPE_TRANSACTION_TYPE,
            &FAIL_CERT, &FAIL_CERT_SIZE));

    /* creating our fail parser should succeed. */
    ASSERT_EQ(VCCERT_STATUS_SUCCESS,
        vccert_parser_init(
            &options, &failparser, FAIL_CERT, FAIL_CERT_SIZE));

    /* attestation should fail with
     * VCCERT_ERROR_PARSER_ATTEST_MISSING_TRANSACTION_TYPE */
    EXPECT_EQ(VCCERT_ERROR_PARSER_ATTEST_MISSING_TRANSACTION_TYPE,
        vccert_parser_attest(&failparser, 77, true));

    /* clean up. */
    dispose((disposable_t*)&failparser);
}

/**
 * A certificate with a missing artifact id fails attestation, if
 * verifyContract is true.
 */
TEST_F(vccert_parser_attest_test, missing_artifact_id)
{
    vccert_parser_context_t failparser;

    uint8_t* FAIL_CERT = 0;
    size_t FAIL_CERT_SIZE = 0;

    /* we should be able to create a signed certificate. */
    ASSERT_EQ(VCCERT_STATUS_SUCCESS,
        create_signed_certificate(
            true, VCCERT_FIELD_TYPE_ARTIFACT_ID,
            &FAIL_CERT, &FAIL_CERT_SIZE));

    /* creating our fail parser should succeed. */
    ASSERT_EQ(VCCERT_STATUS_SUCCESS,
        vccert_parser_init(
            &options, &failparser, FAIL_CERT, FAIL_CERT_SIZE));

    /* attestation should fail with
     * VCCERT_ERROR_PARSER_ATTEST_MISSING_ARTIFACT_ID */
    EXPECT_EQ(VCCERT_ERROR_PARSER_ATTEST_MISSING_ARTIFACT_ID,
        vccert_parser_attest(&failparser, 77, true));

    /* clean up. */
    dispose((disposable_t*)&failparser);
}

/**
 * Dummy transaction resolver.
 */
static bool dummy_txn_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccrypt_buffer_t*, bool*)
{
    return false;
}

/**
 * Dummy artifact state resolver.
 */
static int32_t dummy_artifact_state_resolver(
    void*, void*, const uint8_t*, vccrypt_buffer_t*)
{
    return -1;
}

/**
 * Dummy entity key resolver.
 */
static bool dummy_entity_key_resolver(
    void*, void*, uint64_t, const uint8_t*,
    vccrypt_buffer_t* enc_buffer, vccrypt_buffer_t* sign_buffer)
{
    memcpy(enc_buffer->data, NULL_KEY, 32);
    memcpy(sign_buffer->data, SIGNING_KEY, 32);

    return true;
}

/**
 * Dummy contract.
 */
static bool dummy_contract(
    vccert_parser_context_t*, void*)
{
    return true;
}

/**
 * Fail contract.
 */
static bool fail_contract(
    vccert_parser_context_t*, void*)
{
    return false;
}

/**
 * Dummy disposer.
 */
static void dummy_dispose(void*)
{
}

/**
 * Dummy contract resolver.
 */
static int dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccert_contract_closure_t* closure)
{
    closure->hdr.dispose = &dummy_dispose;
    closure->contract_fn = &dummy_contract;
    closure->context = NULL;

    return VCCERT_STATUS_SUCCESS;
}

/**
 * Fail contract resolver.
 */
static int fail_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccert_contract_closure_t* closure)
{
    closure->hdr.dispose = &dummy_dispose;
    closure->contract_fn = &fail_contract;
    closure->context = NULL;

    return VCCERT_STATUS_SUCCESS;
}

/**
 * Build a signed certificate, skipping the provided field if field skip is
 * enabled.
 */
static int create_signed_certificate(
    bool enable_field_skip,
    int skip_field,
    uint8_t** cert,
    size_t* cert_size)
{
    int retval;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t crypto_suite;
    vccert_builder_options_t builder_opts;
    vccert_builder_context_t builder;
    vccrypt_buffer_t private_key_buffer;
    const uint8_t* local_cert;

    malloc_allocator_options_init(&alloc_opts);

    /* create a crypto suite for this builder. */
    retval =
        vccrypt_suite_options_init(
            &crypto_suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1);
    if (VCCRYPT_STATUS_SUCCESS != retval)
        goto cleanup_alloc_opts;

    /* create builder options. */
    retval =
        vccert_builder_options_init(&builder_opts, &alloc_opts, &crypto_suite);
    if (VCCERT_STATUS_SUCCESS != retval)
        goto cleanup_crypto_suite;

    /* create builder instance. */
    retval =
        vccert_builder_init(&builder_opts, &builder, 1000);
    if (VCCERT_STATUS_SUCCESS != retval)
        goto cleanup_builder_opts;

    /* private key. */
    retval =
        vccrypt_suite_buffer_init_for_signature_private_key(
            &crypto_suite, &private_key_buffer);
    if (VCCRYPT_STATUS_SUCCESS != retval)
        goto cleanup_builder;

    /* copy private key to buffer. */
    retval =
        vccrypt_buffer_read_data(
            &private_key_buffer, PRIVATE_KEY, 64);
    if (VCCERT_STATUS_SUCCESS != retval)
        goto cleanup_private_key_buffer;

    /* certificate version */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_CERTIFICATE_VERSION)
    {
        retval =
            vccert_builder_add_short_uint32(
                &builder, VCCERT_FIELD_TYPE_CERTIFICATE_VERSION,
                0x00010000UL);
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* transaction timestamp */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_CERTIFICATE_VALID_FROM)
    {
        retval =
            vccert_builder_add_short_uint64(
                &builder, VCCERT_FIELD_TYPE_CERTIFICATE_VALID_FROM, 1515987826);
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* crypto suite */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_CERTIFICATE_CRYPTO_SUITE)
    {
        retval =
            vccert_builder_add_short_uint16(
                &builder, VCCERT_FIELD_TYPE_CERTIFICATE_CRYPTO_SUITE, 0x0001);
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* certificate type */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_CERTIFICATE_TYPE)
    {
        retval =
            vccert_builder_add_short_UUID(
                &builder, VCCERT_FIELD_TYPE_CERTIFICATE_TYPE,
                (const uint8_t*)"\x52\xa7\xf0\xfb\x8a\x6b\x4d\x03"
                                "\x86\xa5\x7f\x61\x2f\xcf\x7e\xff");
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* transaction id */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_CERTIFICATE_ID)
    {
        retval =
            vccert_builder_add_short_UUID(
                &builder, VCCERT_FIELD_TYPE_CERTIFICATE_ID,
                (const uint8_t*)"\x1d\x6e\x32\xfa\x1f\x23\x49\xf4"
                                "\xa5\xaa\x57\x05\x48\x93\xc5\xf6");
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* transaction link */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_PREVIOUS_CERTIFICATE_ID)
    {
        retval =
            vccert_builder_add_short_UUID(
                &builder, VCCERT_FIELD_TYPE_PREVIOUS_CERTIFICATE_ID,
                (const uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00");
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* transaction type */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_TRANSACTION_TYPE)
    {
        retval =
            vccert_builder_add_short_UUID(
                &builder, VCCERT_FIELD_TYPE_TRANSACTION_TYPE,
                (const uint8_t*)"\x17\xe1\xfc\x1f\x5d\xd9\x44\xa9"
                                "\xb4\x9d\x1b\x6c\x1e\xb6\xd0\x11");
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* artifact type */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_ARTIFACT_TYPE)
    {
        retval =
            vccert_builder_add_short_UUID(
                &builder, VCCERT_FIELD_TYPE_ARTIFACT_TYPE,
                (const uint8_t*)"\x6d\x34\x1a\x9b\x42\xaf\x45\x3d"
                                "\xac\xdb\x4a\x99\x63\xd9\xd1\x4e");
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* artifact id */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_ARTIFACT_ID)
    {
        retval =
            vccert_builder_add_short_UUID(
                &builder, VCCERT_FIELD_TYPE_ARTIFACT_ID,
                (const uint8_t*)"\x3e\xe2\x99\x7b\x2d\x4f\x48\x2e"
                                "\x86\x58\x88\x86\x06\xd1\x35\x03");
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* previous state */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_PREVIOUS_ARTIFACT_STATE)
    {
        retval =
            vccert_builder_add_short_uint16(
                &builder, VCCERT_FIELD_TYPE_PREVIOUS_ARTIFACT_STATE, 0x0002);
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* next state */
    if (!enable_field_skip || skip_field != VCCERT_FIELD_TYPE_NEW_ARTIFACT_STATE)
    {
        retval =
            vccert_builder_add_short_uint16(
                &builder, VCCERT_FIELD_TYPE_NEW_ARTIFACT_STATE, 0x0003);
        if (VCCERT_STATUS_SUCCESS != retval)
            goto cleanup_private_key_buffer;
    }

    /* sign the certificate */
    retval =
        vccert_builder_sign(
            &builder, SIGNER_ID, &private_key_buffer);
    if (VCCERT_STATUS_SUCCESS != retval)
        goto cleanup_private_key_buffer;

    /* copy the cert on success. */
    local_cert = vccert_builder_emit(&builder, cert_size);
    *cert = (uint8_t*)malloc(*cert_size);
    memcpy(*cert, local_cert, *cert_size);

    /* success. */
    retval = 0;

cleanup_private_key_buffer:
    dispose((disposable_t*)&private_key_buffer);

cleanup_builder:
    dispose((disposable_t*)&builder);

cleanup_builder_opts:
    dispose((disposable_t*)&builder_opts);

cleanup_crypto_suite:
    dispose((disposable_t*)&crypto_suite);

cleanup_alloc_opts:
    dispose((disposable_t*)&alloc_opts);

    return retval;
}
