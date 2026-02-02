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
package eu.europa.ec.eudi.trustvalidator.port.input.trust

import arrow.core.Either
import arrow.core.Either.Companion.catch
import arrow.core.NonEmptyList
import arrow.core.raise.catch
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContext
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.trustvalidator.adapter.out.serialization.X509CertificateChainSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

@Serializable
enum class VerificationContextTO {
    WalletInstanceAttestation,
    WalletUnitAttestation,
    WalletUnitAttestationStatus,
    PID,
    PIDStatus,
    PubEAA,
    PubEAAStatus,
    QEAA,
    QEAAStatus,
    EAA,
    EAAStatus,
    WalletRelyingPartyRegistrationCertificate,
    WalletRelyingPartyAccessCertificate,
    Custom,
}

@Serializable
data class TrustQueryTO(
    @Required
    @Serializable(with = X509CertificateChainSerializer::class)
    val chain: NonEmptyList<X509Certificate>,

    @Required val verificationContext: VerificationContextTO,

    val useCase: String? = null,
)

@Serializable
data class TrustResponseTO(val trusted: Boolean)

@Serializable
data class ErrorResponseTO(val description: String)

fun interface IsChainTrusted {
    suspend operator fun invoke(query: TrustQueryTO): Either<ErrorResponseTO, TrustResponseTO>
}

fun IsChainTrusted(isChainTrustedForContext: IsChainTrustedForContext<List<X509Certificate>, TrustAnchor>): IsChainTrusted =
    IsChainTrusted { query ->
        either {
            val verificationContext = query.verificationContext().bind()
            val result = catch({ isChainTrustedForContext(query.chain, verificationContext) }) { error ->
                CertificationChainValidation.NotTrusted(error)
            }
            ensureNotNull(result) {
                ErrorResponseTO("No configuration found for VerificationContext $verificationContext")
            }

            when (result) {
                is CertificationChainValidation.Trusted -> TrustResponseTO(true)
                is CertificationChainValidation.NotTrusted -> TrustResponseTO(false)
            }
        }
    }

private fun TrustQueryTO.verificationContext(): Either<ErrorResponseTO, VerificationContext> =
    either {
        fun useCase(): String = ensureNotNull(useCase) { ErrorResponseTO("Missing useCase") }
        when (verificationContext) {
            VerificationContextTO.WalletInstanceAttestation -> VerificationContext.WalletInstanceAttestation
            VerificationContextTO.WalletUnitAttestation -> VerificationContext.WalletUnitAttestation
            VerificationContextTO.WalletUnitAttestationStatus -> VerificationContext.WalletUnitAttestationStatus
            VerificationContextTO.PID -> VerificationContext.PID
            VerificationContextTO.PIDStatus -> VerificationContext.PIDStatus
            VerificationContextTO.PubEAA -> VerificationContext.PubEAA
            VerificationContextTO.PubEAAStatus -> VerificationContext.PubEAAStatus
            VerificationContextTO.QEAA -> VerificationContext.QEAA
            VerificationContextTO.QEAAStatus -> VerificationContext.QEAAStatus
            VerificationContextTO.EAA -> VerificationContext.EAA(useCase())
            VerificationContextTO.EAAStatus -> VerificationContext.EAAStatus(useCase())
            VerificationContextTO.WalletRelyingPartyRegistrationCertificate -> VerificationContext.WalletRelyingPartyRegistrationCertificate
            VerificationContextTO.WalletRelyingPartyAccessCertificate -> VerificationContext.WalletRelyingPartyAccessCertificate
            VerificationContextTO.Custom -> VerificationContext.Custom(useCase())
        }
    }
