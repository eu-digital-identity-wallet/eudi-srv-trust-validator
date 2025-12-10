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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.TrustSources
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CValidator
import eu.europa.ec.eudi.verifier.endpoint.domain.ServiceType
import java.security.cert.X509Certificate

fun interface VerifyTrust {
    suspend operator fun invoke(serviceType: ServiceType, x5c: NonEmptyList<X509Certificate>): Either<VerifyTrustError, Boolean>
}

sealed interface VerifyTrustError {
    object UnknownServiceType : VerifyTrustError {
        val error = "Unknown service type"
        val description = "Service type provided does not exist"
    }
}

internal class VerifyTrustLive(
    private val trustSources: TrustSources,
) : VerifyTrust {
    override suspend fun invoke(serviceType: ServiceType, x5c: NonEmptyList<X509Certificate>): Either<VerifyTrustError, Boolean> = either {
        val certs = ensureNotNull(trustSources(serviceType.value)?.toNonEmptyListOrNull()) {
            VerifyTrustError.UnknownServiceType
        }

        val x5CShouldBe = X5CShouldBe(
            rootCACertificates = certs,
        )
        val x5cValidator = X5CValidator(x5CShouldBe)
        x5cValidator.ensureTrusted(x5c)
            .fold(
                ifLeft = { false },
                ifRight = { true },
            )
    }
}
