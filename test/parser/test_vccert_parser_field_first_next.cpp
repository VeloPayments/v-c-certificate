/**
 * \file test_vccert_parser_field_first_next.cpp
 *
 * Test vccert_parser_field_first and vccert_parser_field_next.
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
    void*, void*, uint8_t*, vccrypt_buffer_t*, bool*);
static int32_t dummy_state_resolver(
    void*, void*, uint8_t*);
static vccert_contract_fn_t dummy_contract_resolver(
    void*, void*, uint8_t*, uint8_t*);

static const uint8_t* TEST_CERT = (const uint8_t*)
    //field 0x0001 is 0x01020304
    "\x00\x01\x00\x04\x01\x02\x03\x04"
    //field 0x1002 is "Testing 1 2 3"
    "\x10\x02\x00\x0dTesting 1 2 3"
    //field 0x1735 is 0x01
    "\x17\x35\x00\x01\x01";
static const size_t TEST_CERT_SIZE = 30;

class vccert_parser_field_first_next_test : public ::testing::Test {
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
TEST_F(vccert_parser_field_first_next_test, external_dependencies)
{
    ASSERT_EQ(0, options_init_result);
    ASSERT_EQ(0, suite_init_result);
    ASSERT_EQ(0, parser_init_result);
}

/**
 * Test that we can read the first field and each subsequent field.
 */
TEST_F(vccert_parser_field_first_next_test, field_search)
{
    uint16_t field_id;
    const uint8_t* value;
    size_t size;

    uint32_t field1_val;

    //The first field is 0x0001
    ASSERT_EQ(0, vccert_parser_field_first(&parser, &field_id, &value, &size));
    ASSERT_EQ(0x0001, field_id);
    ASSERT_EQ(4U, size);
    ASSERT_NE((const uint8_t*)NULL, value);
    memcpy(&field1_val, value, sizeof(uint32_t));
    EXPECT_EQ(0x01020304UL, htonl(field1_val));

    //The next field is 0x1002
    ASSERT_EQ(0, vccert_parser_field_next(&parser, &field_id, &value, &size));
    ASSERT_EQ(0x1002, field_id);
    ASSERT_EQ(13U, size);
    ASSERT_NE((const uint8_t*)NULL, value);
    EXPECT_EQ(0, memcmp(value, "Testing 1 2 3", size));

    //find field 0x1735
    ASSERT_EQ(0, vccert_parser_field_next(&parser, &field_id, &value, &size));
    ASSERT_EQ(0x1735, field_id);
    ASSERT_EQ(1U, size);
    ASSERT_NE((const uint8_t*)NULL, value);
    EXPECT_EQ(0x01, *value);

    //no more fields
    ASSERT_NE(0, vccert_parser_field_next(&parser, &field_id, &value, &size));
}

/**
 * Dummy entity resolver.
 */
static bool dummy_entity_resolver(
    void*, void*, uint8_t*, vccrypt_buffer_t*, bool*)
{
    return false;
}

/**
 * Dummy entity state resolver.
 */
static int32_t dummy_state_resolver(
    void*, void*, uint8_t*)
{
    return 0;
}

/**
 * Dummy contract resolver.
 */
static vccert_contract_fn_t dummy_contract_resolver(
    void*, void*, uint8_t*, uint8_t*)
{
    return NULL;
}
