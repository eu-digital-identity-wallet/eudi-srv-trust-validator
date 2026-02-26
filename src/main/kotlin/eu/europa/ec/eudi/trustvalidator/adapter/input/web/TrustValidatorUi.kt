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

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.trustvalidator.adapter.out.Base64CertificateUtils
import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrustedUseCase
import eu.europa.ec.eudi.trustvalidator.port.input.trust.TrustQueryTO
import eu.europa.ec.eudi.trustvalidator.port.input.trust.VerificationContextTO
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*

private val log = LoggerFactory.getLogger(TrustValidatorUi::class.java)

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
        request.createTrustQueryTO()
        val result = either {
            val trustQuery = request.createTrustQueryTO().mapLeft {
                ValidationResult.Error(
                    message = "Invalid input: ${it.message ?: it.javaClass.simpleName}",
                )
            }.bind()

            val trustResponse = isChainTrusted(trustQuery).mapLeft {
                ValidationResult.Error(
                    message = "Chain could not be validated: ${it.description}",
                )
            }.bind()

            val useCaseSuffix = trustQuery.useCase.buildUseCaseText()

            ensure(trustResponse.trusted && trustResponse.trustAnchor != null) {
                ValidationResult.Error(
                    message = "Validation failed for context '${trustQuery.verificationContext}'$useCaseSuffix.",
                )
            }

            val anchor = trustResponse.trustAnchor
            val certificate = anchor.let { cert ->
                Base64CertificateUtils.encode(cert)
            }
            ValidationResult.Success(
                message = "Validation succeeded for context '${trustQuery.verificationContext}'$useCaseSuffix.",
                trustAnchorCertificate = certificate,
                trustAnchorSubject = anchor.subjectX500Principal.name,
            )
        }

        val (validationResult, subject, certificate) = result.fold(
            ifLeft = { Triple(it, null, null) },
            ifRight = { Triple(it, it.trustAnchorSubject, it.trustAnchorCertificate) },
        )

        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "trust-validator-certificate-check-form",
                mapOf(
                    "verificationContexts" to VerificationContextTO.entries.map { it.name },
                    "status" to validationResult.status,
                    "message" to validationResult.message,
                    "trustAnchorSubject" to subject,
                    "trustAnchorCertificate" to certificate,
                ),
            )
    }

    companion object {
        const val TRUST_VALIDATOR_UI: String = "/trust/validator"
    }

    sealed interface ValidationResult {
        val status: String
        val message: String

        @Serializable
        data class Success(
            override val message: String,
            val trustAnchorCertificate: String,
            val trustAnchorSubject: String,
        ) : ValidationResult {
            override val status = "success"
        }

        @Serializable
        data class Error(override val message: String) : ValidationResult {
            override val status = "error"
        }
    }
}

private suspend fun String?.buildUseCaseText(): String? = if (this.isNullOrBlank()) "" else " (use-case: '$this')"

private suspend fun ServerRequest.createTrustQueryTO(): Either<Throwable, TrustQueryTO> = Either.catch {
    val request = this.awaitFormData()
    val x509Certificates = run {
        request.getFirst("certificatesBase64")?.let {
            val certificates = it.trim()
                .lineSequence()
                .map { certificate -> certificate.trim() }
                .filter { certificate -> certificate.isNotEmpty() }
                .toList()

            require(certificates.isNotEmpty()) {
                "Please provide at least one Base64-encoded DER certificate (one per line)."
            }

            val x509Certificates = certificates.map { certificate ->
                Base64CertificateUtils.decode(certificate)
            }
            requireNotNull(x509Certificates.toNonEmptyListOrNull()) { "Certificate chain must not be empty." }
        }
    }
    requireNotNull(x509Certificates) { "Certificate chain must not be empty." }

    val verificationContext = run {
        val verificationContextRaw = request.getFirst("verificationContext")?.trim().orEmpty()
        val verificationContext = verificationContextRaw.ifBlank {
            error("Verification context must be selected.")
        }
        VerificationContextTO.valueOf(verificationContext)
    }

    val useCase = request.getFirst("verificationUseCase")?.trim().orEmpty()

    TrustQueryTO(x509Certificates, verificationContext, useCase)
}
