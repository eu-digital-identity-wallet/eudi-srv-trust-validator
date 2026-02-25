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

import arrow.core.NonEmptyList
import arrow.core.raise.result
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrustedUseCase
import eu.europa.ec.eudi.trustvalidator.port.input.trust.TrustQueryTO
import eu.europa.ec.eudi.trustvalidator.port.input.trust.VerificationContextTO
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.awaitFormData
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.renderAndAwait
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.io.encoding.Base64

/**
 * Web adapter for displaying the Trust Validator UI.
 *
 * @param isChainTrusted use case for verifying trust
 * @property route the routes handled by this web adapter
 */
internal class TrustValidatorUi(
    private val isChainTrusted: IsChainTrustedUseCase,
) {

    val route: RouterFunction<ServerResponse> = coRouter {
        (GET("") or GET("/")) {
            log.info("Redirecting to {}", TRUST_VALIDATOR_UI)
            ServerResponse.status(HttpStatus.TEMPORARY_REDIRECT)
                .renderAndAwait("redirect:$TRUST_VALIDATOR_UI")
        }
        GET(
            TRUST_VALIDATOR_UI,
            contentType(MediaType.ALL) and accept(MediaType.TEXT_HTML),
        ) { handleDisplayTrustValidatorForm() }

        POST(
            TRUST_VALIDATOR_UI,
            contentType(MediaType.APPLICATION_FORM_URLENCODED) and accept(MediaType.TEXT_HTML),
        ) { req -> handleSubmitTrustValidatorForm(req) }
    }

    private suspend fun handleDisplayTrustValidatorForm(): ServerResponse {
        log.info("Displaying 'Trust Validator' page")
        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "trust-validator-certificate-check-form",
                mapOf(
                    "verificationContexts" to VerificationContextTO.entries.map { it.name },
                ),
            )
    }

    private suspend fun handleSubmitTrustValidatorForm(request: ServerRequest): ServerResponse {
        data class ValidationResult(
            val status: String,
            val message: String,
            val trustAnchorCertificate: String? = null,
            val trustAnchorIssuer: String? = null,
        )

        val form = request.awaitFormData()

        val certificatesText = form.getFirst("certificatesBase64")?.trim().orEmpty()
        val verificationContextRaw = form.getFirst("verificationContext")?.trim().orEmpty()
        val useCase = form.getFirst("verificationUseCase")?.trim().orEmpty()

        val result = result {
            val chain = parseCertificates(certificatesText)

            val verificationContext = verificationContextRaw.ifBlank {
                error("Verification context must be selected.")
            }
            val verificationContextTo = VerificationContextTO.valueOf(verificationContext)
            val trustQuery = TrustQueryTO(chain, verificationContextTo, useCase)
            isChainTrusted(trustQuery).fold(
                ifLeft = {
                    ValidationResult(
                        status = "error",
                        message = "Validation failed: unsupported/unknown verification context '$verificationContext'.",
                    )
                },
                ifRight = {
                    val useCaseSuffix = if (useCase.isBlank()) "" else " (use-case: '$useCase')"
                    if (it.trusted) {
                        val anchor = it.trustAnchor
                        val trustAnchorBase64 = anchor?.let { cert ->
                            base64.encode(cert.encoded)
                        }
                        ValidationResult(
                            status = "success",
                            message = "Validation succeeded for context '$verificationContext'$useCaseSuffix.",
                            trustAnchorCertificate = trustAnchorBase64,
                            trustAnchorIssuer = anchor?.issuerX500Principal?.name,
                        )
                    } else {
                        ValidationResult(
                            status = "error",
                            message = "Validation failed for context '$verificationContext'$useCaseSuffix.",
                        )
                    }
                },
            )
        }.getOrElse { e ->
            ValidationResult(
                status = "error",
                message = "Invalid input: ${e.message ?: e.javaClass.simpleName}",
            )
        }

        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "trust-validator-certificate-check-form",
                mapOf(
                    "verificationContexts" to VerificationContextTO.entries.map { it.name },
                    "certificatesBase64" to certificatesText,
                    "selectedContext" to verificationContextRaw,
                    "useCase" to useCase,
                    "status" to result.status,
                    "message" to result.message,
                    "trustAnchorIssuer" to result.trustAnchorIssuer,
                    "trustAnchorCertificate" to result.trustAnchorCertificate,
                ),
            )
    }

    private fun parseCertificates(multipleLineSeparatedCertificates: String): NonEmptyList<X509Certificate> {
        val certificateFactory = CertificateFactory.getInstance("X.509")

        val certificates = multipleLineSeparatedCertificates
            .lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toList()

        require(certificates.isNotEmpty()) {
            "Please provide at least one Base64-encoded DER certificate (one per line)."
        }

        val x509Certificates = certificates.map { certificate ->
            val derEncodedCertificate = base64.decode(certificate)
            certificateFactory.generateCertificate(derEncodedCertificate.inputStream()) as X509Certificate
        }
        return requireNotNull(x509Certificates.toNonEmptyListOrNull()) { "Certificate chain must not be empty." }
    }

    companion object {
        const val TRUST_VALIDATOR_UI: String = "/trust/validator"
        private val log = LoggerFactory.getLogger(TrustValidatorUi::class.java)
        val base64 by lazy { Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL) }
    }
}
