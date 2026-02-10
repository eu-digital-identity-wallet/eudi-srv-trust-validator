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

import eu.europa.ec.eudi.etsi1196x2.consultation.GetTrustAnchorsForSupportedQueries
import eu.europa.ec.eudi.etsi1196x2.consultation.usingKeyStore
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import java.security.KeyStore
import java.security.cert.TrustAnchor

fun <CTX : Any> GetTrustAnchorsForSupportedQueries.Companion.usingKeyStore(
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
    keystore: KeyStore,
    queryPerVerificationContext: Map<CTX, Regex>,
): GetTrustAnchorsForSupportedQueries<CTX, TrustAnchor> =
    GetTrustAnchorsForSupportedQueries.usingKeyStore(
        dispatcher,
        keystore,
        queryPerVerificationContext.keys,
    ) { checkNotNull(queryPerVerificationContext[it]) }

fun <CTX : Any, TRUST_ANCHOR : Any> GetTrustAnchorsForSupportedQueries.Companion.empty():
    GetTrustAnchorsForSupportedQueries<CTX, TRUST_ANCHOR> = GetTrustAnchorsForSupportedQueries(emptySet()) { null }
