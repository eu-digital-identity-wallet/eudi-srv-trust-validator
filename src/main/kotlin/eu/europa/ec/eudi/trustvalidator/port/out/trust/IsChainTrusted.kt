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
package eu.europa.ec.eudi.trustvalidator.port.out.trust

import arrow.core.NonEmptyList

fun interface IsChainTrusted<in CHAIN : Any, in CONTEXT : Any, out TRUST_ANCHOR : Any> {
    suspend operator fun invoke(
        chain: CHAIN,
        context: CONTEXT,
    ): CertificateChainTrust<TRUST_ANCHOR>?
}

sealed interface CertificateChainTrust<out TRUST_ANCHOR : Any> {
    data class Trusted<out TRUST_ANCHOR : Any>(
        val trustAnchor: TRUST_ANCHOR,
    ) : CertificateChainTrust<TRUST_ANCHOR>

    class NotTrusted(
        val reasons: NonEmptyList<Throwable>,
    ) : CertificateChainTrust<Nothing>
}
