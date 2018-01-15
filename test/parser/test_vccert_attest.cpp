/**
 * \file test_vccert_attest.cpp
 *
 * Test vccert_attest.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
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
static vccert_contract_fn_t dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*);
static vccert_contract_fn_t fail_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*);

#if 0
static const uint8_t* PRIVATE_KEY = (const uint8_t*)
    "\x65\x93\x21\xd0\x35\xa9\xf8\xcf"
    "\x35\x37\xd1\xd1\x82\xfd\xee\xf8"
    "\x92\x8e\x0c\xfe\xb4\x56\x4b\x2d"
    "\xb5\x11\x60\x6d\xc6\xf6\x13\xbd"
    "\x47\x83\xe9\xf6\x78\xd1\x49\xac"
    "\xd2\x09\x66\xb0\xab\x88\xf7\xd0"
    "\x5d\x6d\x4f\x54\x0f\x1f\x23\x82"
    "\x86\x00\x3a\xda\x0c\x27\xcc\x35";
#endif
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
    vccert_parser_options_t*, vccert_parser_context_t*)
{
    return true;
}

/**
 * Fail contract.
 */
static bool fail_contract(
    vccert_parser_options_t*, vccert_parser_context_t*)
{
    return false;
}

/**
 * Dummy contract resolver.
 */
static vccert_contract_fn_t dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*)
{
    return &dummy_contract;
}

/**
 * Fail contract resolver.
 */
static vccert_contract_fn_t fail_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*)
{
    return &fail_contract;
}
