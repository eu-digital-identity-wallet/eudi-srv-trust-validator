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
import arrow.core.NonEmptyList
import arrow.core.raise.catch
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContext
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.trustvalidator.adapter.out.serialization.X509CertificateChainSerializer
import eu.europa.ec.eudi.trustvalidator.adapter.out.serialization.X509CertificateSerializer
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
data class TrustResponseTO(
    @Required val trusted: Boolean,
    @Serializable(with = X509CertificateSerializer::class) val trustAnchor: X509Certificate?,
) {
    companion object {
        fun trusted(trustAnchor: X509Certificate) = TrustResponseTO(true, trustAnchor)
        fun notTrusted() = TrustResponseTO(false, null)
    }
}

sealed interface ErrorResponseTO {
    val description: String

    @Serializable
    data class ClientErrorResponseTO(
        @Required override val description: String,
    ) : ErrorResponseTO

    @Serializable
    data class ServerErrorResponseTO(
        @Required override val description: String,
    ) : ErrorResponseTO
}

class IsChainTrustedUseCase(
    private val isChainTrustedForContext: IsChainTrustedForContext<List<X509Certificate>, TrustAnchor>,
) {
    suspend operator fun invoke(query: TrustQueryTO): Either<ErrorResponseTO, TrustResponseTO> =
        either {
            val verificationContext = query.verificationContext().bind()
            val result = catch({ isChainTrustedForContext(query.chain, verificationContext) }) { error ->
                CertificationChainValidation.NotTrusted(error)
            }
            ensureNotNull(result) {
                ErrorResponseTO.ServerErrorResponseTO("No configuration found for VerificationContext $verificationContext")
            }

            when (result) {
                is CertificationChainValidation.Trusted -> {
                    val trustAnchorCertificate = ensureNotNull(result.trustAnchor.trustedCert) {
                        ErrorResponseTO.ServerErrorResponseTO("TrustAnchor was not specified as a X509 Certificate")
                    }
                    TrustResponseTO.trusted(trustAnchorCertificate)
                }
                is CertificationChainValidation.NotTrusted -> TrustResponseTO.notTrusted()
            }
        }
}

private fun TrustQueryTO.verificationContext(): Either<ErrorResponseTO.ClientErrorResponseTO, VerificationContext> =
    either {
        fun useCase(): String = ensureNotNull(useCase) { ErrorResponseTO.ClientErrorResponseTO("Missing useCase") }
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
