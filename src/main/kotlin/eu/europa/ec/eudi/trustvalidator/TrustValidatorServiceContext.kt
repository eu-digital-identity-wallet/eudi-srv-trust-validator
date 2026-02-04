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
import arrow.core.raise.catch
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.etsi1196x2.consultation.*
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.DSSAdapter
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.usingLoTL
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.SwaggerUi
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.TrustApi
import eu.europa.ec.eudi.trustvalidator.adapter.out.scheduling.dss.CleanupDSSCache
import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrustedUseCase
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate
import eu.europa.esig.dss.tsl.source.LOTLSource
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.BeanRegistrarDsl
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.http.codec.CodecCustomizer
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.io.Resource
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import java.net.URI
import java.net.URL
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

private val log = LoggerFactory.getLogger(TrustValidatorServiceContext::class.java)

internal class TrustValidatorServiceContext : BeanRegistrarDsl({
    registerBean { Clock.System }

    registerBean {
        val config = bean<TrustValidatorConfigurationProperties>()
        val trustSources = config.trustSources

        val usingLoTL = IsChainTrustedForContext.usingLoTL(
            sourcePerVerification = trustSources?.lotlSources().orEmpty(),
            validateCertificateChain = ValidateCertificateChainJvm {
                isRevocationEnabled = false
            },
            dssAdapter = DSSAdapter.usingFileCacheDataLoader(
                fileCacheExpiration = 24.hours,
                cacheDirectory = config.dss.cacheLocation,
            ),
            clock = bean<Clock>(),
            ttl = 10.minutes,
        )

        val usingKeyStore = IsChainTrustedForContext(trustSources?.keyStoreSources().orEmpty())

        IsChainTrustedUseCase { chain, context ->
            suspend fun IsChainTrustedForContext<List<X509Certificate>, TrustAnchor>.isTrusted(
                chain: NonEmptyList<X509Certificate>,
                context: VerificationContext,
            ): CertificationChainValidation<TrustAnchor>? =
                catch({ invoke(chain, context) }) {
                    CertificationChainValidation.NotTrusted(it)
                }

            when (val usingLoTL = usingLoTL.isTrusted(chain, context)) {
                is CertificationChainValidation.Trusted -> usingLoTL
                is CertificationChainValidation.NotTrusted -> usingKeyStore.isTrusted(chain, context) ?: usingLoTL
                null -> usingKeyStore.isTrusted(chain, context)
            }
        }
    }

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

@ConfigurationProperties("trust-validator")
data class TrustValidatorConfigurationProperties(
    val dss: DSSConfigurationProperties,
    val trustSources: TrustSourcesConfigurationProperties? = null,
)

data class DSSConfigurationProperties(
    val cacheLocation: Path,
)

data class TrustSourcesConfigurationProperties(
    val walletProviders: LoTLConfigurationProperties? = null,
    val pidProviders: LoTLConfigurationProperties? = null,
    val qeaaProviders: LoTLConfigurationProperties? = null,
    val pubEaaProviders: LoTLConfigurationProperties? = null,
    val eaaProviders: List<EAALoTLConfigurationProperties>? = null,
    val wrpacProviders: LoTLConfigurationProperties? = null,
    val wrprcProviders: LoTLConfigurationProperties? = null,
    val keyStore: KeyStoreConfigurationProperties? = null,
)

data class LoTLConfigurationProperties(
    val location: URL,
    val signatureVerification: KeyStoreConfigurationProperties? = null,
    val issuanceService: URI,
    val revocationService: URI,
)

data class KeyStoreConfigurationProperties(
    val location: Resource,
    val keyStoreType: String = "JKS",
    val password: Password? = null,
) {
    init {
        require(location.exists() && location.isFile && location.isReadable) {
            "location must point to an existing readable file"
        }
    }
}

@JvmInline
value class Password(val value: String) {
    override fun toString(): String = "Password(REDACTED)"
}

data class EAALoTLConfigurationProperties(
    val useCase: String,
    val lotl: LoTLConfigurationProperties,
)

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

private fun LoTLConfigurationProperties.issuanceLoTLSource(): LOTLSource =
    lotlSourceOf(location, signatureVerification, issuanceService)

private fun LoTLConfigurationProperties.revocationLoTLSource(): LOTLSource =
    lotlSourceOf(location, signatureVerification, revocationService)

private fun lotlSourceOf(
    location: URL,
    signatureVerificationKeyStore: KeyStoreConfigurationProperties?,
    serviceType: URI,
): LOTLSource =
    LOTLSource().apply {
        url = location.toExternalForm()
        trustAnchorValidityPredicate = GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate()
        tlVersions = listOf(5, 6)
        trustServicePredicate = { serviceType.toString() == it.serviceInformation.serviceTypeIdentifier }
        if (null != signatureVerificationKeyStore) {
            certificateSource = signatureVerificationKeyStore.location.inputStream.use {
                KeyStoreCertificateSource(
                    it,
                    signatureVerificationKeyStore.keyStoreType,
                    (signatureVerificationKeyStore.password?.value ?: "").toCharArray(),
                )
            }
        }
    }

private fun TrustSourcesConfigurationProperties.lotlSources(): Map<VerificationContext, LOTLSource> =
    buildMap {
        // Wallet Providers
        if (null != walletProviders) {
            log.info("Configuring Wallet Providers using LoTL: $walletProviders")
            val walletProvidersIssuance = walletProviders.issuanceLoTLSource()
            val walletProvidersRevocation = walletProviders.revocationLoTLSource()

            put(VerificationContext.WalletInstanceAttestation, walletProvidersIssuance)
            put(VerificationContext.WalletUnitAttestation, walletProvidersIssuance)
            put(VerificationContext.WalletUnitAttestationStatus, walletProvidersRevocation)
        }

        // PID Providers
        if (null != pidProviders) {
            log.info("Configuring PID Providers using LoTL: $pidProviders")
            put(VerificationContext.PID, pidProviders.issuanceLoTLSource())
            put(VerificationContext.PIDStatus, pidProviders.revocationLoTLSource())
        }

        // QEAA Providers
        if (null != qeaaProviders) {
            log.info("Configuring QEAA Providers using LoTL: $qeaaProviders")
            put(VerificationContext.QEAA, qeaaProviders.issuanceLoTLSource())
            put(VerificationContext.QEAAStatus, qeaaProviders.revocationLoTLSource())
        }

        // PubEAA Providers
        if (null != pubEaaProviders) {
            log.info("Configuring PubEAA Providers using LoTL: $pubEaaProviders")
            put(VerificationContext.PubEAA, pubEaaProviders.issuanceLoTLSource())
            put(VerificationContext.PubEAAStatus, pubEaaProviders.revocationLoTLSource())
        }

        // EAA Providers
        if (!eaaProviders.isNullOrEmpty()) {
            eaaProviders.forEach { eaaProvider ->
                log.info("Configuring EAA Provider ${eaaProvider.useCase} using LoTL: ${eaaProvider.lotl}")
                put(VerificationContext.EAA(eaaProvider.useCase), eaaProvider.lotl.issuanceLoTLSource())
                put(VerificationContext.EAAStatus(eaaProvider.useCase), eaaProvider.lotl.revocationLoTLSource())
            }
        }

        // Wallet Relying Party Access Certificate Providers
        if (null != wrpacProviders) {
            log.info("Configuring WRPAC Providers using LoTL: $wrpacProviders")
            put(VerificationContext.WalletRelyingPartyAccessCertificate, wrpacProviders.issuanceLoTLSource())
        }

        // Wallet Relying Party Registration Certificate Providers
        if (null != wrprcProviders) {
            log.info("Configuring WRPRC Providers using LoTL: $wrprcProviders")
            put(VerificationContext.WalletRelyingPartyRegistrationCertificate, wrprcProviders.issuanceLoTLSource())
        }
    }

private fun TrustSourcesConfigurationProperties.keyStoreSources():
    Map<VerificationContext, IsChainTrusted<List<X509Certificate>, TrustAnchor>> =
    buildMap {
        if (null != keyStore) {
            val isChainTrusted = IsChainTrusted.usingKeystore(
                ValidateCertificateChainJvm {
                    isRevocationEnabled = false
                },
            ) {
                keyStore.location.inputStream.use { inputStream ->
                    KeyStore.getInstance(keyStore.keyStoreType).apply {
                        load(inputStream, (keyStore.password?.value ?: "").toCharArray())
                    }
                }.also {
                    log.info("KeyStore contains the following aliases: ${it.aliases().toList().joinToString(separator = ", ")}")
                }
            }

            // Wallet Providers
            log.info("Configuring Wallet Providers using KeyStore: $keyStore")
            put(VerificationContext.WalletInstanceAttestation, isChainTrusted)
            put(VerificationContext.WalletUnitAttestation, isChainTrusted)
            put(VerificationContext.WalletUnitAttestationStatus, isChainTrusted)

            // PID Providers
            log.info("Configuring PID Providers using KeyStore: $keyStore")
            put(VerificationContext.PID, isChainTrusted)
            put(VerificationContext.PIDStatus, isChainTrusted)

            // QEAA Providers
            log.info("Configuring QEAA Providers using KeyStore: $keyStore")
            put(VerificationContext.QEAA, isChainTrusted)
            put(VerificationContext.QEAAStatus, isChainTrusted)

            // PubEAA Providers
            log.info("Configuring PubEAA Providers using KeyStore: $keyStore")
            put(VerificationContext.PubEAA, isChainTrusted)
            put(VerificationContext.PubEAAStatus, isChainTrusted)

            // EAA Providers
            if (!eaaProviders.isNullOrEmpty()) {
                eaaProviders.forEach { eaaProvider ->
                    log.info("Configuring EAA Provider ${eaaProvider.useCase} using KeyStore: $keyStore")
                    put(VerificationContext.EAA(eaaProvider.useCase), isChainTrusted)
                    put(VerificationContext.EAAStatus(eaaProvider.useCase), isChainTrusted)
                }
            }

            // Wallet Relying Party Access Certificate Providers
            log.info("Configuring WRPAC Providers using KeyStore: $keyStore")
            put(VerificationContext.WalletRelyingPartyAccessCertificate, isChainTrusted)

            // Wallet Relying Party Registration Certificate Providers
            log.info("Configuring WRPRC Providers using KeyStore: $keyStore")
            put(VerificationContext.WalletRelyingPartyRegistrationCertificate, isChainTrusted)
        }
    }
