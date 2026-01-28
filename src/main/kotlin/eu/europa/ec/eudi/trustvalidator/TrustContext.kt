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

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.trustvalidator.adapter.input.timer.RefreshTrustSources
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.SwaggerUi
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.TrustApi
import eu.europa.ec.eudi.trustvalidator.adapter.out.cert.TrustSources
import eu.europa.ec.eudi.trustvalidator.adapter.out.lotl.FetchLOTLCertificatesDSS
import eu.europa.ec.eudi.trustvalidator.domain.*
import eu.europa.ec.eudi.trustvalidator.port.input.VerifyTrust
import eu.europa.ec.eudi.trustvalidator.port.input.VerifyTrustLive
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.BeanRegistrarDsl
import org.springframework.boot.http.codec.CodecCustomizer
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.reactive.config.ApiVersionConfigurer
import org.springframework.web.reactive.config.WebFluxConfigurer
import java.net.URI
import java.security.KeyStore

private val log = LoggerFactory.getLogger(TrustApplication::class.java)

@OptIn(ExperimentalSerializationApi::class)
internal fun beans(clock: Clock) = BeanRegistrarDsl {
    registerBean { clock }

    registerBean { FetchLOTLCertificatesDSS() }

    // Trust sources storage (mutable, updated by scheduler)
    registerBean { TrustSources() }

    // Periodic refresh of trust sources (LOTL and keystore)
    registerBean { RefreshTrustSources(bean(), bean(), bean()) }

    //
    // Config
    //
    registerBean { verifierConfig(env, bean()) }

    //
    // End points
    //

    // VerifyTrust service
    registerBean<VerifyTrust> { VerifyTrustLive(bean()) }

    registerBean {
        val utilityApi = TrustApi(bean())
        val swaggerUi = SwaggerUi(
            publicResourcesBasePath = env.getRequiredProperty("spring.webflux.static-path-pattern").removeSuffix("/**"),
            webJarResourcesBasePath = env.getRequiredProperty("spring.webflux.webjars-path-pattern")
                .removeSuffix("/**"),
        )
        utilityApi.route
            .and(swaggerUi.route)
    }

    //
    // Other
    //
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
    registerBean {
        object : WebFluxConfigurer {
            override fun configureApiVersioning(configurer: ApiVersionConfigurer) {
                configurer.apply {
                    useRequestHeader("API-Version")
                    setVersionRequired(false)
                    setDefaultVersion("1.0.0")
                }
            }
        }
    }
}

private fun verifierConfig(environment: Environment, clock: Clock): ValidatorConfig {
    return ValidatorConfig(
        trustSourcesConfig = environment.trustSources(),
    )
}

/**
 * Parses the trust sources configuration from the environment.
 * Handles array-like property names: trustSources[0].pattern, etc.
 */
private fun Environment.trustSources(): Map<ServiceType, TrustSourceConfig> {
    val trustSourcesConfigMap = mutableMapOf<ServiceType, TrustSourceConfig>()
    val prefix = "trustSources"

    var index = 0
    while (true) {
        val indexPrefix = "$prefix[$index]"
        val providerType = getPropertyOrEnvVariable("$indexPrefix.providerType") ?: break

        // Parse LOTL configuration if present
        val lotlSourceConfig = getPropertyOrEnvVariable("$indexPrefix.lotl.location")?.takeIf { it.isNotBlank() }?.let { lotlLocation ->
            val location = URI(lotlLocation).toURL()
            val serviceTypeFilter = getPropertyOrEnvVariable<ServiceType>("$indexPrefix.lotl.serviceTypeFilter")
            val refreshInterval = getPropertyOrEnvVariable("$indexPrefix.lotl.refreshInterval", "0 0 * * * *")

            val lotlKeystoreConfig = parseKeyStoreConfig("$indexPrefix.lotl.keystore")

            TrustedListConfig(location, serviceTypeFilter, refreshInterval, lotlKeystoreConfig)
        }

        // Parse keystore configuration if present
        val keystoreConfig = parseKeyStoreConfig("$indexPrefix.keystore")

        val serviceType = parseServiceType(providerType)
        if (serviceType == null) {
            log.warn("Unknown providerType '{}' at {} — skipping entry", providerType, indexPrefix)
        } else {
            trustSourcesConfigMap[serviceType] = trustSourcesConfig(lotlSourceConfig, keystoreConfig)
        }

        index++
    }

    return trustSourcesConfigMap
}

private fun parseServiceType(value: String): ServiceType? {
    // Try by enum name first
    return try {
        ServiceType.valueOf(value)
    } catch (_: IllegalArgumentException) {
        // Then try to match by the URL value stored in the enum
        ServiceType.values().firstOrNull { it.value == value }
    }
}

private fun Environment.getPropertyOrEnvVariable(property: String): String? {
    return getProperty(property) ?: getProperty(toEnvironmentVariable(property))
}

private fun Environment.getPropertyOrEnvVariable(property: String, defaultValue: String): String {
    return getProperty(property) ?: getProperty(toEnvironmentVariable(property)) ?: defaultValue
}

private inline fun <reified T> Environment.getPropertyOrEnvVariable(property: String): T? {
    return this.getProperty(key = property) ?: this.getProperty(key = toEnvironmentVariable(property))
}

private fun toEnvironmentVariable(property: String): String {
    return property.replace(".", "_")
        .replace("[", "_")
        .replace("]", "")
        .replace("-", "")
        .uppercase()
}

private fun Environment.parseKeyStoreConfig(propertyPrefix: String): KeyStoreConfig? = getPropertyOrEnvVariable(
    "$propertyPrefix.path",
)?.let { keystorePath ->
    val keystoreType = getPropertyOrEnvVariable("$propertyPrefix.type") ?: "JKS"
    val keystorePassword = getPropertyOrEnvVariable("$propertyPrefix.password", "").toCharArray()
    loadKeystore(keystorePath, keystoreType, keystorePassword)
        .onLeft { log.warn("Failed to load keystore from '$keystorePath'", it) }
        .map { KeyStoreConfig(keystorePath, keystoreType, keystorePassword, it) }
        .getOrNull()
}

private fun loadKeystore(keystorePath: String, keystoreType: String, keystorePassword: CharArray) = Either.catch {
    DefaultResourceLoader().getResource(keystorePath)
        .inputStream
        .use {
            KeyStore.getInstance(keystoreType).apply {
                load(it, keystorePassword)
            }
        }
}

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
