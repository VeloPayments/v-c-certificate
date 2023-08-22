/**
 * \file test_vccert_parser_init.cpp
 *
 * Test the vccert_parser_options_init function.
 *
 * \copyright 2017-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
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

class vccert_parser_options_init_test {
public:
    void setUp()
    {
        vccrypt_suite_register_velo_v1();

        malloc_allocator_options_init(&alloc_opts);

        suite_init_result =
            vccrypt_suite_options_init(&crypto_suite, &alloc_opts,
                VCCRYPT_SUITE_VELO_V1);
    }

    void tearDown()
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

TEST_SUITE(vccert_parser_options_init_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccert_parser_options_init_test fixture; \
    fixture.setUp();

#define END_TEST_F() \
    fixture.tearDown(); \
}

/**
 * Sanity test of external dependencies.
 */
BEGIN_TEST_F(external_dependencies)
    TEST_ASSERT(0 == fixture.suite_init_result);
END_TEST_F()

/**
 * Test parameter checking for init.
 */
BEGIN_TEST_F(parameter_checks)
    vccert_parser_options_t options;

    //test the null check for the options structure
    TEST_ASSERT(
        0
            != vccert_parser_options_init(
                    NULL, &fixture.alloc_opts, &fixture.crypto_suite,
                    &dummy_txn_resolver, &dummy_artifact_state_resolver,
                    &dummy_contract_resolver, &dummy_entity_key_resolver,
                    NULL));

    //test the null check for the allocator
    TEST_ASSERT(
        0
            != vccert_parser_options_init(
                    &options, NULL, &fixture.crypto_suite, &dummy_txn_resolver,
                    &dummy_artifact_state_resolver, &dummy_contract_resolver,
                    &dummy_entity_key_resolver, NULL));

    //test the null check for the crypto suite
    TEST_ASSERT(
        0
            != vccert_parser_options_init(
                    &options, &fixture.alloc_opts, NULL, &dummy_txn_resolver,
                    &dummy_artifact_state_resolver, &dummy_contract_resolver,
                    &dummy_entity_key_resolver, NULL));

    //test the null check for the transaction resolver
    TEST_ASSERT(
        0
            != vccert_parser_options_init(
                    &options, &fixture.alloc_opts, &fixture.crypto_suite, NULL,
                    &dummy_artifact_state_resolver, &dummy_contract_resolver,
                    &dummy_entity_key_resolver, NULL));

    //test the null check for the artifact state resolver
    TEST_ASSERT(
        0
            != vccert_parser_options_init(
                    &options, &fixture.alloc_opts, &fixture.crypto_suite,
                    &dummy_txn_resolver, NULL, &dummy_contract_resolver,
                    &dummy_entity_key_resolver, NULL));

    //test the null check for the contract resolver
    TEST_ASSERT(
        0
            != vccert_parser_options_init(
                    &options, &fixture.alloc_opts, &fixture.crypto_suite,
                    &dummy_txn_resolver, &dummy_artifact_state_resolver, NULL,
                    &dummy_entity_key_resolver, NULL));

    //test the null check for the contract resolver
    TEST_ASSERT(
        0
            != vccert_parser_options_init(
                    &options, &fixture.alloc_opts, &fixture.crypto_suite,
                    &dummy_txn_resolver, &dummy_artifact_state_resolver,
                    &dummy_contract_resolver, NULL, NULL));
END_TEST_F()

/**
 * Test that the options structure is set correctly.
 */
BEGIN_TEST_F(init)
    vccert_parser_options_t options;
    int dummy_context = 7;

    TEST_ASSERT(
        0
            == vccert_parser_options_init(
                    &options, &fixture.alloc_opts, &fixture.crypto_suite,
                    &dummy_txn_resolver, &dummy_artifact_state_resolver,
                    &dummy_contract_resolver, &dummy_entity_key_resolver,
                    &dummy_context));

    TEST_EXPECT((dispose_method_t)NULL != options.hdr.dispose);
    TEST_EXPECT(&fixture.alloc_opts == options.alloc_opts);
    TEST_EXPECT(&fixture.crypto_suite == options.crypto_suite);
    TEST_EXPECT(
        &dummy_txn_resolver == options.parser_options_transaction_resolver);
    TEST_EXPECT(
        &dummy_artifact_state_resolver
            == options.parser_options_artifact_state_resolver);
    TEST_EXPECT(
        &dummy_contract_resolver
            == options.parser_options_contract_resolver);
    TEST_EXPECT(
        &dummy_entity_key_resolver
            == options.parser_options_entity_key_resolver);
    TEST_EXPECT(&dummy_context == options.context);

    //dispose of the structure
    dispose((disposable_t*)&options);
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
