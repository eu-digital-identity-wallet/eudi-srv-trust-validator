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
package eu.europa.ec.eudi.trustvalidator.adapter.out.jades

import arrow.core.raise.result
import eu.europa.ec.eudi.etsi119602.consultation.VerifyJwtSignature
import eu.europa.ec.eudi.trustvalidator.config.KeyStoreConfigurationProperties
import eu.europa.esig.dss.enumerations.Indication
import eu.europa.esig.dss.enumerations.ValidationLevel
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor
import eu.europa.esig.dss.spi.x509.CertificateSource
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.validation.SignedDocumentValidator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Date
import kotlin.time.Clock
import kotlin.time.toJavaInstant

class VerifyJwtSignatureUsingJAdESBB private constructor(
    certificateSource: CertificateSource,
    private val clock: Clock,
) : VerifyJwtSignature {
    private val certificateVerifier: CommonCertificateVerifier =
        CommonCertificateVerifier(true).apply {
            val trustedCertificateSource = CommonTrustedCertificateSource().apply { importAsTrusted(certificateSource) }
            setTrustedCertSources(trustedCertificateSource)
        }

    override suspend fun invoke(jwt: String): VerifyJwtSignature.Outcome =
        result {
            withContext(Dispatchers.IO) {
                val validator =
                    SignedDocumentValidator.fromDocument(InMemoryDocument(jwt.toByteArray())).apply {
                        setCertificateVerifier(certificateVerifier)
                        setValidationLevel(ValidationLevel.BASIC_SIGNATURES)
                        setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE)
                        setValidationTime(Date.from(clock.now().toJavaInstant()))
                    }

                val report = validator.validateDocument().simpleReport
                check(null != report.signatureIdList.singleOrNull()) { "JWT can not contain more than one signature" }

                val signatureId = report.firstSignatureId
                val indication = report.getIndication(signatureId)
                if (indication == Indication.TOTAL_PASSED) {
                    VerifyJwtSignature.Outcome.Verified(jwt)
                } else {
                    VerifyJwtSignature.Outcome.NotVerified(
                        IllegalStateException(
                            "JAdES B-B signature verification failed: indication=$indication, " +
                                "subIndication=${report.getSubIndication(signatureId)}",
                        ),
                    )
                }
            }
        }.getOrElse {
            VerifyJwtSignature.Outcome.NotVerified(
                IllegalStateException("JAdES B-B signature could not be verified", it),
            )
        }

    companion object {
        suspend operator fun invoke(
            keyStore: KeyStoreConfigurationProperties,
            clock: Clock,
        ): VerifyJwtSignatureUsingJAdESBB =
            withContext(Dispatchers.IO) {
                val certificateSource: CertificateSource =
                    keyStore.location.inputStream.use {
                        KeyStoreCertificateSource(
                            it,
                            keyStore.keyStoreType,
                            (keyStore.password?.value ?: "").toCharArray(),
                        )
                    }
                VerifyJwtSignatureUsingJAdESBB(certificateSource, clock)
            }
    }
}
