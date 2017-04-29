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
static bool dummy_entity_resolver(
    void*, void*, const uint8_t*, vccrypt_buffer_t*, bool*);
static int32_t dummy_state_resolver(
    void*, void*, const uint8_t*);
static vccert_contract_fn_t dummy_contract_resolver(
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
    //field 0x0001 is 0x01020304
    "\x00\x01\x00\x04\x01\x02\x03\x04"
    //field 0x1002 is "Testing 1 2 3"
    "\x10\x02\x00\x0dTesting 1 2 3"
    //field 0x1735 is 0x01
    "\x17\x35\x00\x01\x01"
    //field 0x0050 is the signer's UUID
    "\x00\x50\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07"
    "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    //field 0x0051 is the signature
    "\x00\x51\x00\x40\x8d\x7b\x94\x3e\x85\xa1\x17\xda"
    "\x4e\x05\xbc\x90\x08\x89\xd2\x90"
    "\x50\xad\x7d\x78\x99\xb4\x17\xd9"
    "\xe1\xdf\xe5\xa2\x3a\x95\x52\x6e"
    "\x02\xc5\xfd\x71\xcc\x69\x01\x67"
    "\x75\xcf\x0e\x53\x04\xd0\xb4\xff"
    "\x4c\x69\xc7\x8e\xfa\x81\x0e\x8e"
    "\xe9\x35\x38\xbf\x9d\xd8\xad\x0d";
static const size_t TEST_CERT_SIZE = 118;

static const uint8_t* SIGNER_CERT = (const uint8_t*)
    //0x0041 is the artifact ID
    "\x00\x41\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07"
    "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    //0x0053 is the public signing key
    "\x00\x53\x00\x20\x47\x83\xe9\xf6\x78\xd1\x49\xac"
    "\xd2\x09\x66\xb0\xab\x88\xf7\xd0"
    "\x5d\x6d\x4f\x54\x0f\x1f\x23\x82"
    "\x86\x00\x3a\xda\x0c\x27\xcc\x35";
static const size_t SIGNER_CERT_SIZE = 104;

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
                &options, &alloc_opts, &crypto_suite, &dummy_entity_resolver,
                &dummy_state_resolver, &dummy_contract_resolver,
                &dummy_context);

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
    ASSERT_EQ(0, vccert_parser_attest(&parser));

    //the new size should exclude the signature field.
    ASSERT_EQ(TEST_CERT_SIZE, parser.raw_size);
    ASSERT_EQ(TEST_CERT_SIZE - 68, parser.size);
}

/**
 * Dummy entity resolver.
 */
static bool dummy_entity_resolver(
    void* options, void*, const uint8_t*,
    vccrypt_buffer_t* output_buffer, bool* trusted)
{
    vccert_parser_options_t* opts = (vccert_parser_options_t*)options;

    //this resolver will only be called for the signer entity
    vccrypt_buffer_init(output_buffer, opts->alloc_opts, SIGNER_CERT_SIZE);
    memcpy(output_buffer->data, SIGNER_CERT, SIGNER_CERT_SIZE);

    //implicitly trust this certificate
    *trusted = true;

    //entity found
    return true;
}

/**
 * Dummy entity state resolver.
 */
static int32_t dummy_state_resolver(
    void*, void*, const uint8_t*)
{
    return 0;
}

/**
 * Dummy contract resolver.
 */
static vccert_contract_fn_t dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*)
{
    return NULL;
}
