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

fun TrustSourcesConfigurationProperties.keyStoreSources(): Map<VerificationContext, Regex> =
    buildMap {
        val regex = "^.*$".toRegex()

        // Wallet Providers
        put(VerificationContext.WalletInstanceAttestation, regex)
        put(VerificationContext.WalletUnitAttestation, regex)
        put(VerificationContext.WalletUnitAttestationStatus, regex)

        // PID Providers
        put(VerificationContext.PID, regex)
        put(VerificationContext.PIDStatus, regex)

        // QEAA Providers
        put(VerificationContext.QEAA, regex)
        put(VerificationContext.QEAAStatus, regex)

        // PubEAA Providers
        put(VerificationContext.PubEAA, regex)
        put(VerificationContext.PubEAAStatus, regex)

        // EAA Providers
        if (!eaaProviders.isNullOrEmpty()) {
            eaaProviders.forEach { eaaProvider ->
                put(VerificationContext.EAA(eaaProvider.useCase), regex)
                put(VerificationContext.EAAStatus(eaaProvider.useCase), regex)
            }
        }

        // Wallet Relying Party Access Certificate Providers
        put(VerificationContext.WalletRelyingPartyAccessCertificate, regex)

        // Wallet Relying Party Registration Certificate Providers
        put(VerificationContext.WalletRelyingPartyRegistrationCertificate, regex)
    }
