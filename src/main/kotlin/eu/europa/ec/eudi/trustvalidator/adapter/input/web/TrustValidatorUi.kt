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
internal class TrustValidatorUi(isChainTrusted: IsChainTrustedUseCase) {

    private val isChainTrusted = IsChainTrustedUseCaseWebUiAdapter(isChainTrusted)

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
            this@TrustValidatorUi.isChainTrusted::invoke,
        )
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

    companion object {
        const val TRUST_VALIDATOR_UI: String = "/validate"
    }
}

private class IsChainTrustedUseCaseWebUiAdapter(private val isChainTrusted: IsChainTrustedUseCase) {

    suspend operator fun invoke(request: ServerRequest): ServerResponse {
        val formData = request.awaitFormData()

        val trustQuery = TrustQueryTO.fromFormData(formData).getOrElse { response ->
            return response.toServerResponse(formData)
        }

        val trustResponse = isChainTrusted(trustQuery).getOrElse { errorResponseTO ->
            return errorResponseTO.toServerResponse(formData)
        }

        return trustResponse.toServerResponse(formData)
    }

    private fun TrustQueryTO.Companion.fromFormData(formData: MultiValueMap<String, String>): Either<Throwable, TrustQueryTO> =
        Either.catch {
            val x509Certificates = run {
                formData.getFirst("chain")?.trim()
                    ?.lineSequence()
                    ?.map { certificate -> certificate.trim() }
                    ?.filter { certificate -> certificate.isNotEmpty() }
                    ?.map { certificate -> X509CertificateUtils.decodeBase64EncodedDer(certificate) }?.asIterable()
                    ?.toNonEmptyListOrNull()
            }
            requireNotNull(x509Certificates) { "Certificate chain must not be empty." }

            val verificationContext = run {
                val verificationContext = formData.getFirst("verificationContext")
                require(!verificationContext.isNullOrBlank()) { "Verification context must be selected." }

                VerificationContextTO.valueOf(verificationContext)
            }

            val useCase = formData.getFirst("useCase")?.trim()?.takeIf { it.isNotBlank() }

            TrustQueryTO(x509Certificates, verificationContext, useCase)
        }

    private suspend fun Throwable.toServerResponse(formData: MultiValueMap<String, String>): ServerResponse = ServerResponse.badRequest()
        .contentType(MediaType.TEXT_HTML)
        .renderAndAwait(
            "trust-validator-certificate-check-form",
            mapOf(
                "selectedContext" to formData.getFirst("verificationContext"),
                "useCase" to (formData.getFirst("useCase") ?: ""),
                "verificationContexts" to VerificationContextTO.entries.map { it.name },
                "success" to false,
                "messageKey" to "trust.validator.result.error.invalidInput",
                "messageArgs" to (message ?: javaClass.simpleName),
            ),
        )

    private suspend fun ErrorResponseTO.toServerResponse(formData: MultiValueMap<String, String>): ServerResponse {
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
                    "verificationContexts" to VerificationContextTO.entries.map { it.name },
                    "success" to false,
                    "messageKey" to "trust.validator.result.error.fromService",
                    "messageArgs" to description,
                ),
            )
    }

    private suspend fun TrustResponseTO.toServerResponse(formData: MultiValueMap<String, String>): ServerResponse {
        val model = buildMap {
            put("chain", formData.getFirst("chain"))
            put("selectedContext", formData.getFirst("verificationContext"))
            put("useCase", formData.getFirst("useCase"))
            put("verificationContexts", VerificationContextTO.entries.map { it.name })
            put("success", trusted)

            if (trusted) {
                val trustAnchor = checkNotNull(this@toServerResponse.trustAnchor)
                val certificate = X509CertificateUtils.base64Encode(trustAnchor)
                put("trustAnchorSubject", trustAnchor.subjectX500Principal?.name)
                put("trustAnchorCertificate", certificate)
                put("messageKey", "trust.validator.result.success.trusted")
            } else {
                put("messageKey", "trust.validator.result.error.notTrusted")
            }
        }

        return ServerResponse.ok()
            .contentType(MediaType.TEXT_HTML)
            .renderAndAwait("trust-validator-certificate-check-form", model)
    }
}
