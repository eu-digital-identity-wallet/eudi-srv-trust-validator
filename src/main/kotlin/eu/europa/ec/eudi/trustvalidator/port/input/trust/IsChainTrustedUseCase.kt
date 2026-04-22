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
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext.*
import eu.europa.ec.eudi.trustvalidator.adapter.out.serialization.X509CertificateChainSerializer
import eu.europa.ec.eudi.trustvalidator.adapter.out.serialization.X509CertificateSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

@Serializable
enum class VerificationContextTO {
    WalletProviderAttestation,
    WalletOrKeyStorageStatus,

    @Deprecated("WalletInstanceAttestation has been deprecated", ReplaceWith("WalletProviderAttestation"))
    WalletInstanceAttestation,

    @Deprecated("WalletUnitAttestation has been deprecated", ReplaceWith("WalletProviderAttestation"))
    WalletUnitAttestation,

    @Deprecated("WalletUnitAttestationStatus has been deprecated is deprecated", ReplaceWith("WalletOrKeyStorageStatus"))
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
    WalletRelyingPartyRegistrationCertificateStatus,
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
    init {
        require(!trusted || null != trustAnchor)
    }
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
    private val isChainTrusted: IsChainTrustedForContextF<List<X509Certificate>, VerificationContext, TrustAnchor>,
) {
    suspend operator fun invoke(query: TrustQueryTO): Either<ErrorResponseTO, TrustResponseTO> =
        either {
            val verificationContext = query.verificationContext().bind()
            val result = catch({ isChainTrusted(query.chain, verificationContext) }) { error ->
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
            VerificationContextTO.WalletInstanceAttestation -> WalletInstanceAttestation
            VerificationContextTO.WalletUnitAttestation -> WalletUnitAttestation
            VerificationContextTO.WalletUnitAttestationStatus -> WalletUnitAttestationStatus
            VerificationContextTO.WalletProviderAttestation -> WalletInstanceAttestation
            VerificationContextTO.WalletOrKeyStorageStatus -> WalletUnitAttestationStatus
            VerificationContextTO.PID -> PID
            VerificationContextTO.PIDStatus -> PIDStatus
            VerificationContextTO.PubEAA -> PubEAA
            VerificationContextTO.PubEAAStatus -> PubEAAStatus
            VerificationContextTO.QEAA -> QEAA
            VerificationContextTO.QEAAStatus -> QEAAStatus
            VerificationContextTO.EAA -> EAA(useCase())
            VerificationContextTO.EAAStatus -> EAAStatus(useCase())
            VerificationContextTO.WalletRelyingPartyRegistrationCertificate -> WalletRelyingPartyRegistrationCertificate
            VerificationContextTO.WalletRelyingPartyAccessCertificate -> WalletRelyingPartyAccessCertificate
            VerificationContextTO.WalletRelyingPartyRegistrationCertificateStatus -> WalletRelyingPartyRegistrationCertificateStatus
            VerificationContextTO.Custom -> Custom(useCase())
        }
    }
