/**
 * \file test_vccert_parser_init.cpp
 *
 * Test the vccert_parser_options_init function.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

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

class vccert_parser_options_init_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        vccrypt_suite_register_velo_v1();

        malloc_allocator_options_init(&alloc_opts);

        suite_init_result =
            vccrypt_suite_options_init(&crypto_suite, &alloc_opts,
                VCCRYPT_SUITE_VELO_V1);
    }

    void TearDown() override
    {
        if (suite_init_result == 0)
        {
            dispose((disposable_t*)&crypto_suite);
        }

        dispose((disposable_t*)&alloc_opts);
    }

    int suite_init_result;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t crypto_suite;
};

/**
 * Sanity test of external dependencies.
 */
TEST_F(vccert_parser_options_init_test, external_dependencies)
{
    ASSERT_EQ(0, suite_init_result);
}

/**
 * Test parameter checking for init.
 */
TEST_F(vccert_parser_options_init_test, parameter_checks)
{
    vccert_parser_options_t options;

    //test the null check for the options structure
    ASSERT_NE(0,
        vccert_parser_options_init(
            NULL, &alloc_opts, &crypto_suite, &dummy_entity_resolver,
            &dummy_state_resolver, &dummy_contract_resolver, NULL));

    //test the null check for the allocator
    ASSERT_NE(0,
        vccert_parser_options_init(
            &options, NULL, &crypto_suite, &dummy_entity_resolver,
            &dummy_state_resolver, &dummy_contract_resolver, NULL));

    //test the null check for the crypto suite
    ASSERT_NE(0,
        vccert_parser_options_init(
            &options, &alloc_opts, NULL, &dummy_entity_resolver,
            &dummy_state_resolver, &dummy_contract_resolver, NULL));

    //test the null check for the entity resolver
    ASSERT_NE(0,
        vccert_parser_options_init(
            &options, &alloc_opts, &crypto_suite, NULL,
            &dummy_state_resolver, &dummy_contract_resolver, NULL));

    //test the null check for the entity state resolver
    ASSERT_NE(0,
        vccert_parser_options_init(
            &options, &alloc_opts, &crypto_suite, &dummy_entity_resolver,
            NULL, &dummy_contract_resolver, NULL));

    //test the null check for the contract resolver
    ASSERT_NE(0,
        vccert_parser_options_init(
            &options, &alloc_opts, &crypto_suite, &dummy_entity_resolver,
            &dummy_state_resolver, NULL, NULL));
}

/**
 * Test that the options structure is set correctly.
 */
TEST_F(vccert_parser_options_init_test, init)
{
    vccert_parser_options_t options;
    int dummy_context = 7;

    ASSERT_EQ(0,
        vccert_parser_options_init(
            &options, &alloc_opts, &crypto_suite, &dummy_entity_resolver,
            &dummy_state_resolver, &dummy_contract_resolver, &dummy_context));

    EXPECT_NE((dispose_method_t)NULL, options.hdr.dispose);
    EXPECT_EQ(&alloc_opts, options.alloc_opts);
    EXPECT_EQ(&crypto_suite, options.crypto_suite);
    EXPECT_EQ(&dummy_entity_resolver, options.parser_options_entity_resolver);
    EXPECT_EQ(&dummy_state_resolver,
        options.parser_options_entity_state_resolver);
    EXPECT_EQ(&dummy_contract_resolver,
        options.parser_options_contract_resolver);
    EXPECT_EQ(&dummy_context, options.context);

    //dispose of the structure
    dispose((disposable_t*)&options);
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
