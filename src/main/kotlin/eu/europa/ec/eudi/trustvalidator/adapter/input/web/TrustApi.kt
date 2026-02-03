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
package eu.europa.ec.eudi.trustvalidator.adapter.input.web

import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrustedUseCase
import eu.europa.ec.eudi.trustvalidator.port.input.trust.TrustQueryTO
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.badRequest
import org.springframework.web.reactive.function.server.ServerResponse.ok

internal class TrustApi(
    private val isChainTrusted: IsChainTrustedUseCase,
) {
    val route: RouterFunction<ServerResponse> = coRouter {
        POST(
            TRUST_V2,
            contentType(APPLICATION_JSON) and accept(APPLICATION_JSON),
            ::trustQueryV2,
        )
    }

    private suspend fun trustQueryV2(request: ServerRequest): ServerResponse {
        val trustQuery = request.awaitBody<TrustQueryTO>()
        return isChainTrusted(trustQuery).fold(
            { badRequest().bodyValueAndAwait(it) },
            { ok().bodyValueAndAwait(it) },
        )
    }

    companion object {
        const val TRUST_V2 = "/v2/trust"
    }
}
