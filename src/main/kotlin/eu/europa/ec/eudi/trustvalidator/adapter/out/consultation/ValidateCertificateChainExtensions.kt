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
import eu.europa.ec.eudi.etsi1196x2.consultation.ValidateCertificateChain
import eu.europa.ec.eudi.etsi1196x2.consultation.ValidateCertificateChainJvm
import java.math.BigInteger
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

infix fun <CHAIN : Any, TRUST_ANCHOR : Any> ValidateCertificateChain<CHAIN, TRUST_ANCHOR>.or(
    other: ValidateCertificateChain<CHAIN, TRUST_ANCHOR>,
): ValidateCertificateChain<CHAIN, TRUST_ANCHOR> = ValidateCertificateChain { chain, trustAnchors ->
    when (val thisResult = this(chain, trustAnchors)) {
        is CertificationChainValidation.Trusted -> thisResult
        is CertificationChainValidation.NotTrusted -> other(chain, trustAnchors)
    }
}

private data class X509CertificateIdentify(val subject: X500Principal, val serialNumber: BigInteger)

private val X509Certificate.identity: X509CertificateIdentify
    get() = X509CertificateIdentify(subjectX500Principal, serialNumber)

fun ValidateCertificateChain.Companion.direct(): ValidateCertificateChain<List<X509Certificate>, TrustAnchor> =
    ValidateCertificateChain { chain, trustAnchors ->
        require(chain.isNotEmpty()) { "Chain must not be empty" }
        val endEntity = chain.first().identity
        val maybeTrustAnchor = trustAnchors.list.firstOrNull { endEntity == it.trustedCert.identity }
        maybeTrustAnchor?.let {
            CertificationChainValidation.Trusted(it)
        } ?: CertificationChainValidation.NotTrusted(IllegalArgumentException("End-entity X509Certificate does not match any TrustAnchor"))
    }

fun ValidateCertificateChain.Companion.pkix(
    customization: PKIXParameters.() -> Unit,
): ValidateCertificateChain<List<X509Certificate>, TrustAnchor> = ValidateCertificateChainJvm(customization = customization)
