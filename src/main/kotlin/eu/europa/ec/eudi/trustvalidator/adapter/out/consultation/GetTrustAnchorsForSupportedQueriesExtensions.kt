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

import eu.europa.ec.eudi.etsi1196x2.consultation.GetTrustAnchors
import eu.europa.ec.eudi.etsi1196x2.consultation.GetTrustAnchorsForSupportedQueries
import eu.europa.ec.eudi.etsi1196x2.consultation.GetTrustAnchorsForSupportedQueries.Outcome
import eu.europa.ec.eudi.etsi1196x2.consultation.NonEmptyList
import eu.europa.ec.eudi.etsi1196x2.consultation.SensitiveApi

/**
 * Gets a new [GetTrustAnchorsForSupportedQueries] that queries both [this] and [other] for a given [CONTEXT].
 */
@SensitiveApi
infix fun <CONTEXT : Any, TRUST_ANCHOR : Any> GetTrustAnchorsForSupportedQueries<CONTEXT, TRUST_ANCHOR>.and(
    other: GetTrustAnchorsForSupportedQueries<CONTEXT, TRUST_ANCHOR>,
): GetTrustAnchorsForSupportedQueries<CONTEXT, TRUST_ANCHOR> {
    val getTrustAnchors: GetTrustAnchors<CONTEXT, TRUST_ANCHOR> = {
        val fromFirstSource = invoke(it).trustAnchorsOrNull()?.list.orEmpty()
        val fromSecondSource = other.invoke(it).trustAnchorsOrNull()?.list.orEmpty()
        NonEmptyList.nelOrNull(fromFirstSource + fromSecondSource)
    }
    return GetTrustAnchorsForSupportedQueries(supportedQueries + other.supportedQueries, getTrustAnchors)
}

private fun <TRUST_ANCHOR : Any> Outcome<TRUST_ANCHOR>.trustAnchorsOrNull(): NonEmptyList<TRUST_ANCHOR>? =
    (this as? Outcome.Found<TRUST_ANCHOR>)?.trustAnchors
