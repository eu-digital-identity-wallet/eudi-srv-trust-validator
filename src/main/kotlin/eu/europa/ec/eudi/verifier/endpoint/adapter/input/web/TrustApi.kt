/*
 * Copyright (c) 2023 European Commission
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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import arrow.core.Either
import arrow.core.NonEmptyList
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.x5c.X509CertificateChainSerializer
import eu.europa.ec.eudi.verifier.endpoint.domain.ProviderType
import eu.europa.ec.eudi.verifier.endpoint.port.input.VerifyTrust
import kotlinx.serialization.Serializable
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.RequestPredicates.version
import org.springframework.web.reactive.function.server.ServerResponse.badRequest
import org.springframework.web.reactive.function.server.ServerResponse.ok
import java.security.cert.X509Certificate

internal class TrustApi(
    private val verifyTrust: VerifyTrust,
) {
    val route: RouterFunction<ServerResponse> = coRouter {
        POST(
            TRUST_QUERY,
            contentType(APPLICATION_JSON) and accept(APPLICATION_JSON) and version("1.0.0"),
            ::trustQuery,
        )
    }

    private suspend fun trustQuery(request: ServerRequest): ServerResponse {
        val body = Either
            .catch { request.awaitBody<TrustQueryRequest>() }
            .fold(
                ifLeft = { e ->
                    return badRequest().json().bodyValueAndAwait(ErrorResponse("Invalid request body: ${e.message}"))
                },
                ifRight = { it },
            )

        val serviceType = body.serviceType.toDomain()

        return verifyTrust(serviceType, body.x5c).fold(
            ifLeft = { error ->
                badRequest().json().bodyValueAndAwait(error)
            },
            ifRight = { trusted ->
                ok().contentType(APPLICATION_JSON).bodyValueAndAwait(TrustQueryResponse(trusted))
            },
        )
    }

    companion object {
        const val TRUST_QUERY = "/trust"
    }
}

@Serializable
internal data class TrustQueryRequest(
    @Serializable(with = X509CertificateChainSerializer::class)
    val x5c: NonEmptyList<X509Certificate>,
    val serviceType: ProviderType,
)

@Serializable
internal data class TrustQueryResponse(
    val trusted: Boolean,
)

@Serializable
internal data class ErrorResponse(
    val error: String,
)
