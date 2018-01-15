/**
 * \file test_vccert_parser_init.cpp
 *
 * Test the vccert_parser_init function.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

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

class vccert_parser_init_test : public ::testing::Test {
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

        dispose((disposable_t*)&alloc_opts);
    }

    int suite_init_result, options_init_result;
    int dummy_context;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t crypto_suite;
    vccert_parser_options_t options;
};

/**
 * Sanity test of external dependencies.
 */
TEST_F(vccert_parser_init_test, external_dependencies)
{
    ASSERT_EQ(0, options_init_result);
    ASSERT_EQ(0, suite_init_result);
}

/**
 * Test parameter checking for init.
 */
TEST_F(vccert_parser_init_test, parameter_checks)
{
    vccert_parser_context_t context;
    const uint8_t* cert = (const uint8_t*)"1234";
    size_t size = 4;

    //test the null check for the options structure
    ASSERT_NE(0,
        vccert_parser_init(NULL, &context, cert, size));

    //test the null check for the context structure
    ASSERT_NE(0,
        vccert_parser_init(&options, NULL, cert, size));

    //test the null check for the certificate buffer
    ASSERT_NE(0,
        vccert_parser_init(&options, &context, NULL, size));

    //test the zero check for the size
    ASSERT_NE(0,
        vccert_parser_init(&options, &context, cert, 0));
}

/**
 * Test that the parser context structure is set correctly.
 */
TEST_F(vccert_parser_init_test, init)
{
    vccert_parser_context_t context;
    const uint8_t* cert = (const uint8_t*)"1234";
    size_t size = 4;

    //init should return 0 on success
    ASSERT_EQ(0,
        vccert_parser_init(&options, &context, cert, size));

    EXPECT_NE((dispose_method_t)NULL, context.hdr.dispose);
    EXPECT_EQ(&options, context.options);
    EXPECT_EQ(cert, context.cert);
    EXPECT_EQ(size, context.raw_size);
    EXPECT_EQ(size, context.size);
    EXPECT_EQ(NULL, context.parent_buffer.data);
    EXPECT_EQ(0U, context.parent_buffer.size);
    EXPECT_EQ(NULL, context.parent);

    dispose((disposable_t*)&context);
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
    void*, void*, uint64_t, const uint8_t*, vccrypt_buffer_t*,
    vccrypt_buffer_t*)
{
    return false;
}

/**
 * Dummy contract resolver.
 */
static vccert_contract_fn_t dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*)
{
    return NULL;
}
