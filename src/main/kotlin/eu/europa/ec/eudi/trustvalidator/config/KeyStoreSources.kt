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
package eu.europa.ec.eudi.trustvalidator.config

import eu.europa.ec.eudi.etsi1196x2.consultation.*
import eu.europa.ec.eudi.trustvalidator.adapter.out.consultation.or
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.KeyStore
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

private val log = LoggerFactory.getLogger("isChainTrustedForContextUsingKeyStore")

suspend fun TrustSourcesConfigurationProperties.isChainTrustedForContextUsingKeyStore():
    IsChainTrustedForContext<List<X509Certificate>, VerificationContext, TrustAnchor>? =
    keyStore?.let {
        val supportedVerificationContexts = configuredVerificationContexts()
        log.info(supportedVerificationContexts)

        IsChainTrustedForContext.usingKeyStore(
            keystore = loadKeyStore(it),
            supportedVerificationContexts = supportedVerificationContexts,
            validateCertificateChain = ValidateCertificateChainUsingDirectTrustJvm or ValidateCertificateChainUsingPKIXJvm {
                isRevocationEnabled = false
            },
            regexPerVerificationContext = { "^.*$".toRegex() },
        )
    }

private fun TrustSourcesConfigurationProperties.configuredVerificationContexts(): Set<VerificationContext> =
    buildSet {
        fun TrustedListsConfigurationProperties?.isConfigured(): Boolean = null != this && (null != lotl || null != lote)
        fun EAALoTLConfigurationProperties.isConfigured(): Boolean = null != lotl || null != lote

        if (walletProviders.isConfigured()) {
            add(VerificationContext.WalletInstanceAttestation)
            add(VerificationContext.WalletUnitAttestation)
            add(VerificationContext.WalletUnitAttestationStatus)
        }

        if (pidProviders.isConfigured()) {
            add(VerificationContext.PID)
            add(VerificationContext.PIDStatus)
        }

        if (qeaaProviders.isConfigured()) {
            add(VerificationContext.QEAA)
            add(VerificationContext.QEAAStatus)
        }

        if (pubEaaProviders.isConfigured()) {
            add(VerificationContext.PubEAA)
            add(VerificationContext.PubEAAStatus)
        }

        eaaProviders.orEmpty()
            .filter { it.isConfigured() }
            .forEach { eaaProvider ->
                add(VerificationContext.EAA(eaaProvider.useCase))
                add(VerificationContext.EAAStatus(eaaProvider.useCase))
            }

        if (wrpacProviders.isConfigured()) {
            add(VerificationContext.WalletRelyingPartyAccessCertificate)
        }

        if (wrprcProviders.isConfigured()) {
            add(VerificationContext.WalletRelyingPartyRegistrationCertificate)
        }
    }

private suspend fun loadKeyStore(config: KeyStoreConfigurationProperties): KeyStore =
    withContext(Dispatchers.IO) {
        KeyStore.getInstance(config.keyStoreType)
            .apply {
                config.location.inputStream.use {
                    load(it, (config.password?.value ?: "").toCharArray())
                }
            }
    }

private fun Logger.info(configuredVerificationContext: Set<VerificationContext>) {
    configuredVerificationContext.forEach { context -> info("Configured VerificationContext $context using KeyStore") }
}
