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
import eu.europa.ec.eudi.etsi1196x2.consultation.DisposableContainer
import eu.europa.ec.eudi.etsi1196x2.consultation.DisposableScope
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.SensitiveApi
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.etsi1196x2.consultation.cached
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.ConcurrentCacheDataLoader
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.DssOptions
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.GetTrustAnchorsFromLoTL
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.SwaggerUi
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.TrustApi
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.TrustValidatorUi
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.empty
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.or
import eu.europa.ec.eudi.trustvalidator.adapter.out.scheduling.dss.CleanupDSSCache
import eu.europa.ec.eudi.trustvalidator.config.TrustValidatorConfigurationProperties
import eu.europa.ec.eudi.trustvalidator.config.isChainTrustedForContextUsingKeyStore
import eu.europa.ec.eudi.trustvalidator.config.isChainTrustedForContextUsingLoTE
import eu.europa.ec.eudi.trustvalidator.config.isChainTrustedForContextUsingLoTL
import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrustedUseCase
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.springframework.beans.factory.BeanRegistrarDsl
import org.springframework.beans.factory.DisposableBean
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
import java.security.cert.X509Certificate
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

@OptIn(SensitiveApi::class)
internal class TrustValidatorServiceContext : BeanRegistrarDsl({
    registerBean { Clock.System }

    registerBean(infrastructure = true, autowirable = false) { SpringDisposableContainer() }

    registerBean(name = "dss-executor", infrastructure = true, autowirable = false) { Executors.newCachedThreadPool() }

    registerBean(name = "get-trust-anchors-from-lotl", infrastructure = true, autowirable = false) {
        val config = bean<TrustValidatorConfigurationProperties>()
        val scope = bean<DisposableScope>()
        val getTrustAnchorsFromLoTL = GetTrustAnchorsFromLoTL(
            DssOptions(
                loader = ConcurrentCacheDataLoader(
                    DssOptions.DefaultHttpLoader,
                    24.hours,
                    config.dss.cacheLocation,
                ),
                executorService = bean<ExecutorService>("dss-executor"),
            ),
        ).cached(clock = bean(), ttl = 10.minutes, expectedQueries = 50)
        with(scope) {
            getTrustAnchorsFromLoTL.bind()
        }
    }

    registerBean(name = "is-chain-trusted-using-lotl", infrastructure = true, autowirable = false) {
        val config = bean<TrustValidatorConfigurationProperties>()
        config.trustSources?.isChainTrustedForContextUsingLoTL(bean("get-trust-anchors-from-lotl")) ?: IsChainTrustedForContextF.empty()
    }

    registerBean(name = "is-chain-trusted-using-keyStore", infrastructure = true, autowirable = false) {
        val config = bean<TrustValidatorConfigurationProperties>()
        runBlocking {
            config.trustSources?.isChainTrustedForContextUsingKeyStore()
        } ?: IsChainTrustedForContextF.empty()
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

    registerBean(name = "is-chain-trusted-using-lote", infrastructure = true, autowirable = false) {
        val config = bean<TrustValidatorConfigurationProperties>()
        config.trustSources?.isChainTrustedForContextUsingLoTE(
            bean(),
            config.lote.cacheLocation,
            bean(),
            ContinueOnProblem.Never,
            LoadLoTEAndPointers.Constraints.LoadOtherPointers(
                otherLoTEParallelism = 2,
                maxDepth = 1,
                maxLists = 50,
            ),
        ) ?: IsChainTrustedForContextF.empty()
    }

    registerBean {
        val isChainTrustedUsingLoTL =
            bean<IsChainTrustedForContextF<List<X509Certificate>, VerificationContext, TrustAnchor>>("is-chain-trusted-using-lotl")
        val isChainTrustedUsingLoTE =
            bean<IsChainTrustedForContextF<List<X509Certificate>, VerificationContext, TrustAnchor>>("is-chain-trusted-using-lote")
        val isChainTrustedUsingKeyStore =
            bean<IsChainTrustedForContextF<List<X509Certificate>, VerificationContext, TrustAnchor>>("is-chain-trusted-using-keyStore")

        isChainTrustedUsingLoTL or isChainTrustedUsingLoTE or isChainTrustedUsingKeyStore
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

private class SpringDisposableContainer : DisposableContainer(), DisposableBean {
    override fun destroy() {
        dispose()
    }
}
