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
import eu.europa.ec.eudi.etsi1196x2.consultation.*
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.DssOptions
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.usingLoTL
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.SwaggerUi
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.TrustApi
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.empty
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.usingKeyStore
import eu.europa.ec.eudi.trustvalidator.adapter.out.scheduling.dss.CleanupDSSCache
import eu.europa.ec.eudi.trustvalidator.config.KeyStoreConfigurationProperties
import eu.europa.ec.eudi.trustvalidator.config.TrustValidatorConfigurationProperties
import eu.europa.ec.eudi.trustvalidator.config.keyStoreSources
import eu.europa.ec.eudi.trustvalidator.config.lotlSources
import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrustedUseCase
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
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
import java.security.KeyStore
import java.security.cert.TrustAnchor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

private val log = LoggerFactory.getLogger(TrustValidatorServiceContext::class.java)

@OptIn(SensitiveApi::class)
internal class TrustValidatorServiceContext : BeanRegistrarDsl({
    registerBean { Clock.System }

    registerBean(name = "dss-executor", infrastructure = true, autowirable = false, lazyInit = true) { Executors.newCachedThreadPool() }

    registerBean(name = "get-trust-anchors-from-lotl", infrastructure = true, autowirable = false) {
        val config = bean<TrustValidatorConfigurationProperties>()
        val queryPerVerificationContext = config.trustSources?.lotlSources()
            ?.also {
                it.entries.forEach { (context, lotl) -> log.info("Configured VerificationContext $context using LoTL ${lotl.url}") }
            }

        if (!queryPerVerificationContext.isNullOrEmpty())
            GetTrustAnchorsForSupportedQueries.usingLoTL(
                clock = bean(),
                ttl = 10.minutes,
                dssOptions = DssOptions.usingFileCacheDataLoader(
                    fileCacheExpiration = 24.hours,
                    cacheDirectory = config.dss.cacheLocation,
                    executorService = bean<ExecutorService>("dss-executor"),
                ),
                queryPerVerificationContext = queryPerVerificationContext,
            )
        else GetTrustAnchorsForSupportedQueries.empty()
    }

    registerBean(name = "get-trust-anchors-from-keystore", infrastructure = true, autowirable = false) {
        val config = bean<TrustValidatorConfigurationProperties>()
        val keyStoreConfig = config.trustSources?.keyStore
        val queryPerVerificationContext = config.trustSources?.keyStoreSources()
            ?.also {
                it.entries.forEach { (context, _) -> log.info("Configured VerificationContext $context using KeyStore") }
            }

        if (null != keyStoreConfig && !queryPerVerificationContext.isNullOrEmpty())
            GetTrustAnchorsForSupportedQueries.usingKeyStore(
                clock = bean(),
                ttl = 10.minutes,
                keystore = loadKeyStore(keyStoreConfig),
                queryPerVerificationContext = queryPerVerificationContext,
            )
        else GetTrustAnchorsForSupportedQueries.empty()
    }

    registerBean {
        val validateCertificateChain = ValidateCertificateChainJvm { isRevocationEnabled = false }
        val getTrustAnchorsFromLoTL =
            bean<GetTrustAnchorsForSupportedQueries<VerificationContext, TrustAnchor>>("get-trust-anchors-from-lotl")
        val getTrustAnchorsFromKeyStore =
            bean<GetTrustAnchorsForSupportedQueries<VerificationContext, TrustAnchor>>("get-trust-anchors-from-keystore")

        IsChainTrustedForEUDIW(
            validateCertificateChain,
            getTrustAnchorsFromLoTL,
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
        trustApi.route.and(swaggerUi.route)
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

private fun loadKeyStore(config: KeyStoreConfigurationProperties): KeyStore =
    KeyStore.getInstance(config.keyStoreType)
        .apply {
            config.location.inputStream.use {
                load(it, (config.password?.value ?: "").toCharArray())
            }
        }
