/**
 * \file test_certificate_types.cpp
 *
 * Test that certificate types match specification document.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <cstring>
#include <gtest/gtest.h>
#include <vccert/certificate_types.h>
#include <vccrypt/buffer.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

/**
 * Test each certificate type against expected values.
 */
TEST(certificate_types_test, match)
{
    vccrypt_buffer_t buf;
    vccrypt_buffer_t hex_buf;
    allocator_options_t alloc_opts;

    /* set up */
    malloc_allocator_options_init(&alloc_opts);
    ASSERT_EQ(0, vccrypt_buffer_init(&buf, &alloc_opts, 16));
    ASSERT_EQ(0,
        vccrypt_buffer_init_for_hex_serialization(&hex_buf, &alloc_opts, 16));

    /* test root block certificate type */
    const char* ROOT_BLOCK = "a231383da63d474386aa61fb03a38f39";
    ASSERT_EQ(0, vccrypt_buffer_read_data(&hex_buf, ROOT_BLOCK, 32));
    ASSERT_EQ(0, vccrypt_buffer_read_hex(&buf, &hex_buf));
    ASSERT_EQ(0, memcmp(buf.data, vccert_certificate_type_uuid_root_block, 16));

    /* test root entity create transaction certificate type */
    const char* ROOT_ENTITY_CREATE = "1f2e615b585b46cc9ffc95d618c11b92";
    ASSERT_EQ(0, vccrypt_buffer_read_data(&hex_buf, ROOT_ENTITY_CREATE, 32));
    ASSERT_EQ(0, vccrypt_buffer_read_hex(&buf, &hex_buf));
    ASSERT_EQ(0, memcmp(buf.data, vccert_certificate_type_uuid_txn_root_entity_create, 16));

    /* test root entity destroy transaction certificate type */
    const char* ROOT_ENTITY_DESTROY = "b5fc204cf5444c30a53bc97bbd33b8c6";
    ASSERT_EQ(0, vccrypt_buffer_read_data(&hex_buf, ROOT_ENTITY_DESTROY, 32));
    ASSERT_EQ(0, vccrypt_buffer_read_hex(&buf, &hex_buf));
    ASSERT_EQ(0, memcmp(buf.data, vccert_certificate_type_uuid_txn_root_entity_destroy, 16));

    /* test block transaction certificate type. */
    const char* BLOCK_TRANSACTION = "734eacd28b134a37aa02bef5628a6c68";
    ASSERT_EQ(0, vccrypt_buffer_read_data(&hex_buf, BLOCK_TRANSACTION, 32));
    ASSERT_EQ(0, vccrypt_buffer_read_hex(&buf, &hex_buf));
    ASSERT_EQ(0, memcmp(buf.data, vccert_certificate_type_uuid_txn_block, 16));

    /* test transaction certificate type. */
    const char* TRANSACTION = "52a7f0fb8a6b4d0386a57f612fcf7eff";
    ASSERT_EQ(0, vccrypt_buffer_read_data(&hex_buf, TRANSACTION, 32));
    ASSERT_EQ(0, vccrypt_buffer_read_hex(&buf, &hex_buf));
    ASSERT_EQ(0, memcmp(buf.data, vccert_certificate_type_uuid_txn, 16));

    /* test private entity certificate type. */
    const char* PRIVATE_ENTITY = "814e6a7487aa45959d31bcc627cfe44e";
    ASSERT_EQ(0, vccrypt_buffer_read_data(&hex_buf, PRIVATE_ENTITY, 32));
    ASSERT_EQ(0, vccrypt_buffer_read_hex(&buf, &hex_buf));
    ASSERT_EQ(0, memcmp(buf.data, vccert_certificate_type_uuid_private_entity, 16));

    const char* AGENT_SUBTYPE = "9985d93731d44aa78222c317878d5373";
    ASSERT_EQ(0, vccrypt_buffer_read_data(&hex_buf, AGENT_SUBTYPE, 32));
    ASSERT_EQ(0, vccrypt_buffer_read_hex(&buf, &hex_buf));
    ASSERT_EQ(0, memcmp(buf.data, vccert_certificate_type_uuid_agent_subtype, 16));

    /* clean up */
    dispose((disposable_t*)&buf);
    dispose((disposable_t*)&hex_buf);
    dispose((disposable_t*)&alloc_opts);
}
