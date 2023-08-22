/**
 * \file test_vccert_parser_init.cpp
 *
 * Test the vccert_parser_init function.
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

class vccert_parser_init_test {
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

        dispose((disposable_t*)&alloc_opts);
    }

    int suite_init_result, options_init_result;
    int dummy_context;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t crypto_suite;
    vccert_parser_options_t options;
};

TEST_SUITE(vccert_parser_init_test);

#define BEGIN_TEST_F(name) \
TEST(name) \
{ \
    vccert_parser_init_test fixture; \
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
END_TEST_F()

/**
 * Test parameter checking for init.
 */
BEGIN_TEST_F(parameter_checks)
    vccert_parser_context_t context;
    const uint8_t* cert = (const uint8_t*)"1234";
    size_t size = 4;

    //test the null check for the options structure
    TEST_ASSERT(0 != vccert_parser_init(NULL, &context, cert, size));

    //test the null check for the context structure
    TEST_ASSERT(0 != vccert_parser_init(&fixture.options, NULL, cert, size));

    //test the null check for the certificate buffer
    TEST_ASSERT(
        0 != vccert_parser_init(&fixture.options, &context, NULL, size));

    //test the zero check for the size
    TEST_ASSERT(0 != vccert_parser_init(&fixture.options, &context, cert, 0));
END_TEST_F()

/**
 * Test that the parser context structure is set correctly.
 */
BEGIN_TEST_F(init)
    vccert_parser_context_t context;
    const uint8_t* cert = (const uint8_t*)"1234";
    size_t size = 4;

    //init should return 0 on success
    TEST_ASSERT(
        0
            == vccert_parser_init(&fixture.options, &context, cert, size));

    TEST_EXPECT((dispose_method_t)NULL != context.hdr.dispose);
    TEST_EXPECT(&fixture.options == context.options);
    TEST_EXPECT(cert == context.cert);
    TEST_EXPECT(size == context.raw_size);
    TEST_EXPECT(size == context.size);
    TEST_EXPECT(NULL == context.parent_buffer.data);
    TEST_EXPECT(0U == context.parent_buffer.size);
    TEST_EXPECT(NULL == context.parent);

    dispose((disposable_t*)&context);
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
