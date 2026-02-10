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

import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate
import eu.europa.esig.dss.tsl.source.LOTLSource
import java.net.URI
import java.net.URL

fun TrustSourcesConfigurationProperties.lotlSources(): Map<VerificationContext, LOTLSource> =
    buildMap {
        // Wallet Providers
        if (null != walletProviders) {
            val walletProvidersIssuance = walletProviders.issuanceLoTLSource()
            val walletProvidersRevocation = walletProviders.revocationLoTLSource()

            put(VerificationContext.WalletInstanceAttestation, walletProvidersIssuance)
            put(VerificationContext.WalletUnitAttestation, walletProvidersIssuance)
            put(VerificationContext.WalletUnitAttestationStatus, walletProvidersRevocation)
        }

        // PID Providers
        if (null != pidProviders) {
            put(VerificationContext.PID, pidProviders.issuanceLoTLSource())
            put(VerificationContext.PIDStatus, pidProviders.revocationLoTLSource())
        }

        // QEAA Providers
        if (null != qeaaProviders) {
            put(VerificationContext.QEAA, qeaaProviders.issuanceLoTLSource())
            put(VerificationContext.QEAAStatus, qeaaProviders.revocationLoTLSource())
        }

        // PubEAA Providers
        if (null != pubEaaProviders) {
            put(VerificationContext.PubEAA, pubEaaProviders.issuanceLoTLSource())
            put(VerificationContext.PubEAAStatus, pubEaaProviders.revocationLoTLSource())
        }

        // EAA Providers
        if (!eaaProviders.isNullOrEmpty()) {
            eaaProviders.forEach { eaaProvider ->
                put(VerificationContext.EAA(eaaProvider.useCase), eaaProvider.lotl.issuanceLoTLSource())
                put(VerificationContext.EAAStatus(eaaProvider.useCase), eaaProvider.lotl.revocationLoTLSource())
            }
        }

        // Wallet Relying Party Access Certificate Providers
        if (null != wrpacProviders) {
            put(VerificationContext.WalletRelyingPartyAccessCertificate, wrpacProviders.issuanceLoTLSource())
        }

        // Wallet Relying Party Registration Certificate Providers
        if (null != wrprcProviders) {
            put(VerificationContext.WalletRelyingPartyRegistrationCertificate, wrprcProviders.issuanceLoTLSource())
        }
    }

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
