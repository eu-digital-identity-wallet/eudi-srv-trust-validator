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
import arrow.core.getOrElse
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.trustvalidator.adapter.out.x509.X509CertificateUtils
import eu.europa.ec.eudi.trustvalidator.port.input.trust.ErrorResponseTO
import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrustedUseCase
import eu.europa.ec.eudi.trustvalidator.port.input.trust.TrustQueryTO
import eu.europa.ec.eudi.trustvalidator.port.input.trust.TrustResponseTO
import eu.europa.ec.eudi.trustvalidator.port.input.trust.VerificationContextTO
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.util.MultiValueMap
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
                    "verificationContext" to VerificationContextTO.entries.map { it.name },
                ),
            )
    }

    typealias FormData = MultiValueMap<String, String>

    private suspend fun handleSubmitTrustValidatorForm(request: ServerRequest): ServerResponse {
        suspend fun Throwable.toServerResponse(formData: FormData): ServerResponse = ServerResponse.badRequest()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait(
                "trust-validator-certificate-check-form",
                mapOf(
                    "selectedContext" to formData.getFirst("verificationContext"),
                    "useCase" to (formData.getFirst("useCase") ?: ""),
                    "verificationContext" to VerificationContextTO.entries.map { it.name },
                    "status" to "error",
                    "message" to "Invalid input: ${this.message ?: this.javaClass.simpleName}",
                ),
            )

        suspend fun ErrorResponseTO.toServerResponse(formData: FormData): ServerResponse {
            val httpStatusCode = when (this) {
                is ErrorResponseTO.ClientErrorResponseTO -> HttpStatus.BAD_REQUEST
                is ErrorResponseTO.ServerErrorResponseTO -> HttpStatus.INTERNAL_SERVER_ERROR
            }
            return ServerResponse.status(httpStatusCode)
                .contentType(MediaType.TEXT_HTML)
                .renderAndAwait(
                    "trust-validator-certificate-check-form",
                    mapOf(
                        "chain" to formData.getFirst("chain"),
                        "selectedContext" to formData.getFirst("verificationContext"),
                        "useCase" to (formData.getFirst("useCase") ?: ""),
                        "verificationContext" to VerificationContextTO.entries.map { it.name },
                        "status" to "error",
                        "message" to this.description,
                    ),
                )
        }

        suspend fun TrustResponseTO.toServerResponse(formData: FormData): ServerResponse {
            return if (!this.trusted) {
                ServerResponse.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .renderAndAwait(
                        "trust-validator-certificate-check-form",
                        mapOf(
                            "chain" to formData.getFirst("chain"),
                            "selectedContext" to formData.getFirst("verificationContext"),
                            "useCase" to (formData.getFirst("useCase") ?: ""),
                            "verificationContext" to VerificationContextTO.entries.map { it.name },
                            "status" to "error",
                            "message" to "Chain is not trusted for context " +
                                "'${formData.getFirst("verificationContext")}' " +
                                "${ (formData.getFirst("useCase") ?: "")}.",
                        ),
                    )
            } else {
                val trustAnchor = checkNotNull(this.trustAnchor)
                val certificate = X509CertificateUtils.base64Encode(trustAnchor)
                ServerResponse.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .renderAndAwait(
                        "trust-validator-certificate-check-form",
                        mapOf(
                            "chain" to formData.getFirst("chain"),
                            "selectedContext" to formData.getFirst("verificationContext"),
                            "useCase" to (formData.getFirst("useCase") ?: ""),
                            "verificationContext" to VerificationContextTO.entries.map { it.name },
                            "status" to "success",
                            "message" to "Validation succeeded for context " +
                                "'${formData.getFirst("verificationContext")}' " +
                                "${ (formData.getFirst("useCase") ?: "")}.",
                            "trustAnchorSubject" to trustAnchor.subjectX500Principal?.name,
                            "trustAnchorCertificate" to certificate,
                        ),
                    )
            }
        }

        val formData = request.awaitFormData()
        val trustQuery = request.createTrustQueryTO().getOrElse { response ->
            return@handleSubmitTrustValidatorForm response.toServerResponse(formData)
        }

        val trustResponse = isChainTrusted(trustQuery).getOrElse { errorResponseTO ->
            return@handleSubmitTrustValidatorForm errorResponseTO.toServerResponse(formData)
        }

        return trustResponse.toServerResponse(formData)
    }

    companion object {
        const val TRUST_VALIDATOR_UI: String = "/trust/validator"
    }
}

private suspend fun ServerRequest.createTrustQueryTO(): Either<Throwable, TrustQueryTO> = Either.catch {
    val request = this.awaitFormData()
    val x509Certificates = run {
        request.getFirst("chain")?.trim()
            ?.lineSequence()
            ?.map { certificate -> certificate.trim() }
            ?.filter { certificate -> certificate.isNotEmpty() }
            ?.map { certificate -> X509CertificateUtils.decodeBase64EncodedDer(certificate) }?.asIterable()
            ?.toNonEmptyListOrNull()
    }
    requireNotNull(x509Certificates) { "Certificate chain must not be empty." }

    val verificationContext = run {
        val verificationContext = request.getFirst("verificationContext")
        require(!verificationContext.isNullOrBlank()) { "Verification context must be selected." }

        VerificationContextTO.valueOf(verificationContext)
    }

    val useCase = request.getFirst("useCase")?.trim()?.takeIf { it.isNotBlank() }

    TrustQueryTO(x509Certificates, verificationContext, useCase)
}
