/*
 * Copyright (c) 2025-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.trustvalidator.adapter.out.consultation

import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.SensitiveApi

@SensitiveApi
infix fun <CHAIN : Any, CONTEXT : Any, TRUST_ANCHOR : Any> IsChainTrustedForContextF<CHAIN, CONTEXT, TRUST_ANCHOR>.or(
    other: IsChainTrustedForContextF<CHAIN, CONTEXT, TRUST_ANCHOR>,
): IsChainTrustedForContextF<CHAIN, CONTEXT, TRUST_ANCHOR> =
    IsChainTrustedForContextF { chain, context ->
        when (val thisResult = this(chain, context)) {
            is CertificationChainValidation.Trusted -> thisResult
            is CertificationChainValidation.NotTrusted, null -> {
                val otherResult = other(chain, context)
                otherResult ?: thisResult
            }
        }
    }

fun <CHAIN : Any, CONTEXT : Any, TRUST_ANCHOR : Any> IsChainTrustedForContextF.Companion.empty():
    IsChainTrustedForContextF<CHAIN, CONTEXT, TRUST_ANCHOR> =
    IsChainTrustedForContextF { _, _ -> CertificationChainValidation.NotTrusted(IllegalArgumentException("Not trusted")) }
