/**
 * \file vccert_contract_closure_call.c
 *
 * Call a closure method.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vccert/fields.h>
#include <vccert/parser.h>
#include <vccrypt/compare.h>
#include <vpr/parameters.h>

/**
 * \brief Call the given contract closure with the given parser context.
 *
 * \param closure           The closure to call.
 * \param parser            The parser context for this call.
 *
 * \returns the result of executing the contract.
 *      - true if this certificate passes the contract.
 *      - false if this certificate fails the contract.
 */
bool vccert_contract_closure_call(
    vccert_contract_closure_t* closure,
    vccert_parser_context_t* parser)
{
    MODEL_ASSERT(NULL != closure);
    MODEL_ASSERT(NULL != parser);

    return closure->contract_fn(parser, closure->context);
}
