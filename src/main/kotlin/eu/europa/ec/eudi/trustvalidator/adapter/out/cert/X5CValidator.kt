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
package eu.europa.ec.eudi.trustvalidator.adapter.out.cert

import arrow.core.Either
import arrow.core.Nel
import arrow.core.NonEmptyList
import java.security.cert.*

typealias ConfigurePKIXParameters = PKIXParameters.() -> Unit

internal val SkipRevocation: ConfigurePKIXParameters = { isRevocationEnabled = false }

/**
 * The chain should always be trusted in [certificate chain validator][X5CValidator]
 *
 * @param rootCACertificates list of trusted root CA certificates. To be used as trust anchors
 * @param customizePKIX a way to parameterize [PKIXParameters]. If not provided, revocation checks are disabled
 */
data class X5CShouldBe(
    val rootCACertificates: NonEmptyList<X509Certificate>,
    val customizePKIX: ConfigurePKIXParameters = SkipRevocation,
)

class X5CValidator(private val x5CShouldBe: X5CShouldBe) {

    fun ensureTrusted(
        chain: Nel<X509Certificate>,
    ): Either<CertPathValidatorException, Nel<X509Certificate>> =
        Either.catchOrThrow {
            trustedOrThrow(chain)
            chain
        }

    @Throws(CertPathValidatorException::class)
    fun trustedOrThrow(chain: Nel<X509Certificate>) = trustedOrThrow(chain, x5CShouldBe)
}

@Throws(CertPathValidatorException::class)
private fun trustedOrThrow(
    chain: Nel<X509Certificate>,
    trusted: X5CShouldBe,
) {
    val factory = CertificateFactory.getInstance("X.509")
    val certPath = factory.generateCertPath(chain)

    val pkixParameters = trusted.asPkixParameters()
    val validator = CertPathValidator.getInstance("PKIX")

    validator.validate(certPath, pkixParameters)
}

private fun X5CShouldBe.asPkixParameters(): PKIXParameters {
    val trust = rootCACertificates.map { cert -> TrustAnchor(cert, null) }.toSet()
    return PKIXParameters(trust).apply(customizePKIX)
}
