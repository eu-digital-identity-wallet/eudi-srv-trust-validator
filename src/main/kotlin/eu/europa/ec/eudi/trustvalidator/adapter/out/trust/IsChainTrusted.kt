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
package eu.europa.ec.eudi.trustvalidator.adapter.out.trust

import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.trustvalidator.port.out.trust.CertificateChainTrust
import eu.europa.ec.eudi.trustvalidator.port.out.trust.IsChainTrusted

fun <CHAIN : Any, CONTEXT : Any, TRUST_ANCHOR : Any> IsChainTrusted(
    first: IsChainTrustedForContextF<CHAIN, CONTEXT, TRUST_ANCHOR>,
    vararg remaining: IsChainTrustedForContextF<CHAIN, CONTEXT, TRUST_ANCHOR>,
): IsChainTrusted<CHAIN, CONTEXT, TRUST_ANCHOR> {
    suspend infix fun CertificateChainTrust<TRUST_ANCHOR>?.or(
        other: suspend () -> CertificateChainTrust<TRUST_ANCHOR>?,
    ): CertificateChainTrust<TRUST_ANCHOR>? =
        when (this) {
            is CertificateChainTrust.Trusted -> {
                this
            }

            is CertificateChainTrust.NotTrusted -> {
                when (val otherResult = other()) {
                    is CertificateChainTrust.Trusted -> otherResult
                    is CertificateChainTrust.NotTrusted -> CertificateChainTrust.NotTrusted(reasons + otherResult.reasons)
                    null -> this
                }
            }

            null -> {
                other()
            }
        }

    fun <TRUST_ANCHOR : Any> CertificateChainTrust(value: CertificationChainValidation<TRUST_ANCHOR>): CertificateChainTrust<TRUST_ANCHOR> =
        when (value) {
            is CertificationChainValidation.Trusted -> CertificateChainTrust.Trusted(value.trustAnchor)
            is CertificationChainValidation.NotTrusted -> CertificateChainTrust.NotTrusted(nonEmptyListOf(value.cause))
        }

    val delegates = nonEmptyListOf(first, *remaining)
    return IsChainTrusted { chain, context ->
        delegates.fold(null) { accumulator, current ->
            accumulator or { current(chain, context)?.let { CertificateChainTrust(it) } }
        }
    }
}
