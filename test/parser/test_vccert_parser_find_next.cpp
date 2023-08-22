/**
 * \file test_vccert_parser_find_next.cpp
 *
 * Test vccert_parser_find_next.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <minunit/minunit.h>
#include <string.h>
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

static const uint8_t* TEST_CERT = (const uint8_t*)
    //field 0x0001 is 0x01020304
    "\x00\x01\x00\x04\x01\x02\x03\x04"
    //field 0x7002 is 0x01
    "\x70\x02\x00\x01\x01"
    //field 0x0001 is 0xFFFFFFFF
    "\x00\x01\x00\x04\xFF\xFF\xFF\xFF"
    //field 0x7007 is 0x13
    "\x70\x07\x00\x01\x13"
    //field 0x7000 is 0x56
    "\x70\x00\x00\x01\x56"
    //field 0x0001 is 0x77777777
    "\x00\x01\x00\x04\x77\x77\x77\x77";
static const size_t TEST_CERT_SIZE = 39;

class vccert_parser_find_next_test {
public:
    void setUp()
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

    void tearDown()
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

TEST_SUITE(vccert_parser_find_next_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccert_parser_find_next_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * Sanity test of external dependencies.
 */
BEGIN_TEST_F(external_dependencies)
    TEST_ASSERT(0 == fixture.options_init_result);
    TEST_ASSERT(0 == fixture.suite_init_result);
    TEST_ASSERT(0 == fixture.parser_init_result);
END_TEST_F()

/**
 * Test that each 0x0001 field can be found, and the values and sizes are
 * correct.
 */
BEGIN_TEST_F(next)
    const uint8_t* value;
    size_t size;

    uint32_t field1_val;

    //find field 0x0001
    TEST_ASSERT(
        0 == vccert_parser_find_short(&fixture.parser, 0x0001, &value, &size));
    TEST_ASSERT(4U == size);
    TEST_ASSERT((const uint8_t*)NULL != value);
    memcpy(&field1_val, value, sizeof(uint32_t));
    TEST_EXPECT(0x01020304UL == htonl(field1_val));

    //find the next field 0x0001
    TEST_ASSERT(0 == vccert_parser_find_next(&fixture.parser, &value, &size));
    TEST_ASSERT(4U == size);
    TEST_ASSERT((const uint8_t*)NULL != value);
    memcpy(&field1_val, value, sizeof(uint32_t));
    TEST_EXPECT(0xFFFFFFFFUL == htonl(field1_val));

    //find the next field 0x0001
    TEST_ASSERT(0 == vccert_parser_find_next(&fixture.parser, &value, &size));
    TEST_ASSERT(4U == size);
    TEST_ASSERT((const uint8_t*)NULL != value);
    memcpy(&field1_val, value, sizeof(uint32_t));
    TEST_EXPECT(0x77777777UL == htonl(field1_val));

    //There are no more 0x0001 fields
    TEST_ASSERT(0 != vccert_parser_find_next(&fixture.parser, &value, &size));
END_TEST_F()

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
    void*, void*, uint64_t, const uint8_t*, vccrypt_buffer_t*,
    vccrypt_buffer_t*)
{
    return false;
}

/**
 * Dummy contract resolver.
 */
static int dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*,
    vccert_contract_closure_t*)
{
    return VCCERT_ERROR_PARSER_ATTEST_MISSING_CONTRACT;
}
