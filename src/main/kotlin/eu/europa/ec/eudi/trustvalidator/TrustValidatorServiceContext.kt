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
package eu.europa.ec.eudi.trustvalidator

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.etsi119602.consultation.ContinueOnProblem
import eu.europa.ec.eudi.etsi119602.consultation.LoadLoTEAndPointers
import eu.europa.ec.eudi.etsi1196x2.consultation.*
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.SwaggerUi
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.TrustApi
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.TrustValidatorUi
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.and
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.direct
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.or
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.pkix
import eu.europa.ec.eudi.trustvalidator.adapter.out.scheduling.dss.CleanupDSSCache
import eu.europa.ec.eudi.trustvalidator.config.*
import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrustedUseCase
import eu.europa.esig.dss.tsl.source.LOTLSource
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.springframework.beans.factory.BeanRegistrarDsl
import org.springframework.boot.http.codec.CodecCustomizer
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import java.security.cert.TrustAnchor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.time.Clock

@OptIn(SensitiveApi::class)
internal class TrustValidatorServiceContext : BeanRegistrarDsl({
    registerBean { Clock.System }

    registerBean(name = "dss-executor", infrastructure = true, autowirable = false) { Executors.newCachedThreadPool() }

    registerBean(name = "get-trust-anchors-using-lotl", infrastructure = true, autowirable = false) {
        val config = bean<TrustValidatorConfigurationProperties>()
        config.trustSources?.getTrustAnchorsUsingLoTL(
            clock = bean(),
            cacheDirectory = config.dss.cacheLocation,
            executorService = bean<ExecutorService>("dss-executor"),
        ) ?: GetTrustAnchors { null }
    }

    registerBean(infrastructure = true) {
        HttpClient(CIO) {
            install(ContentNegotiation) {
                json(
                    Json {
                        ignoreUnknownKeys = true
                        encodeDefaults = false
                        explicitNulls = false
                    },
                )
            }
        }
    }

    registerBean(name = "get-trust-anchors-using-lote", infrastructure = true, autowirable = false) {
        val config = bean<TrustValidatorConfigurationProperties>()
        val constraints = LoadLoTEAndPointers.Constraints(
            otherLoTEParallelism = 2,
            maxDepth = 1,
            maxLists = 50,
        )
        runBlocking {
            config.trustSources?.getTrustAnchorsUsingLoTE(
                httpClient = bean(),
                continueOnProblem = ContinueOnProblem.Never,
                constraints = constraints,
            )
        } ?: GetTrustAnchorsForSupportedQueries.empty()
    }

    registerBean {
        val config = bean<TrustValidatorConfigurationProperties>()
        val getTrustAnchorsFromLoTL = run {
            val getTrustAnchorsFromLoTL = bean<GetTrustAnchors<LOTLSource, TrustAnchor>>("get-trust-anchors-using-lotl")
            val lotlSources = config.trustSources?.lotlSources() ?: emptyMap()
            GetTrustAnchorsForSupportedQueries.transform(getTrustAnchorsFromLoTL, lotlSources)
        }
        val getTrustAnchorsFromLoTE =
            bean<GetTrustAnchorsForSupportedQueries<VerificationContext, TrustAnchor>>("get-trust-anchors-using-lote")
        val getTrustAnchorsFromKeyStore =
            config.trustSources?.getTrustAnchorsUsingKeyStore() ?: GetTrustAnchorsForSupportedQueries.empty()

        IsChainTrustedForEUDIW(
            ValidateCertificateChain.direct() or ValidateCertificateChain.pkix { isRevocationEnabled = false },
            getTrustAnchorsFromLoTL and getTrustAnchorsFromLoTE,
        ).recoverWith { getTrustAnchorsFromKeyStore }
    }

    registerBean<IsChainTrustedUseCase>()

    registerBean {
        val configuration = bean<TrustValidatorConfigurationProperties>()
        CleanupDSSCache(configuration.dss.cacheLocation)
    }

    registerBean {
        val trustApi = TrustApi(bean())
        val swaggerUi = SwaggerUi(
            publicResourcesBasePath =
                env.getRequiredProperty("spring.webflux.static-path-pattern").removeSuffix("/**"),
            webJarResourcesBasePath =
                env.getRequiredProperty("spring.webflux.webjars-path-pattern").removeSuffix("/**"),
        )
        val trustValidatorUi = TrustValidatorUi(bean())
        trustApi.route.and(swaggerUi.route).and(trustValidatorUi.route)
    }

    registerBean {
        CodecCustomizer {
            val json = Json {
                explicitNulls = false
                ignoreUnknownKeys = true
            }

            it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
            it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
            it.defaultCodecs().enableLoggingRequestDetails(true)
        }
    }

    registerBean {
        val http = bean<ServerHttpSecurity>()
        http {
            cors { // cross-origin resource sharing configuration
                configurationSource = CorsConfigurationSource {
                    CorsConfiguration().apply {
                        fun getOptionalList(name: String): NonEmptyList<String>? =
                            env.getOptionalList(name = name, filter = { it.isNotBlank() }, transform = { it.trim() })

                        allowedOrigins = getOptionalList("cors.origins")
                        allowedOriginPatterns = getOptionalList("cors.originPatterns")
                        allowedMethods = getOptionalList("cors.methods")
                        run {
                            val headers = getOptionalList("cors.headers")
                            allowedHeaders = headers
                            exposedHeaders = headers
                        }
                        allowCredentials = env.getProperty<Boolean>("cors.credentials")
                        maxAge = env.getProperty<Long>("cors.maxAge")
                    }
                }
            }
            csrf { disable() } // cross-site request forgery disabled
        }
    }
})

/**
 * Gets the value of a property that contains a comma-separated list. A list is returned when it contains values.
 *
 * @receiver the configured Spring [Environment] from which to load the property
 * @param name the property to load
 * @param filter optional filter to apply to the list value
 * @param transform optional mapping to apply to the list values
 */
private fun Environment.getOptionalList(
    name: String,
    filter: (String) -> Boolean = { true },
    transform: (String) -> String = { it },
): NonEmptyList<String>? =
    this.getProperty(name)
        ?.split(",")
        ?.filter { filter(it) }
        ?.map { transform(it) }
        ?.toNonEmptyListOrNull()

private fun <CTX : Any, TRUST_ANCHOR : Any> GetTrustAnchorsForSupportedQueries.Companion.empty():
    GetTrustAnchorsForSupportedQueries<CTX, TRUST_ANCHOR> = GetTrustAnchorsForSupportedQueries(emptySet()) { null }
