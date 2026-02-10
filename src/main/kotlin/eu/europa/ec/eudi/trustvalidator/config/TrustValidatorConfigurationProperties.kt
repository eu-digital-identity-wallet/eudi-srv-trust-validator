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

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.Resource
import java.net.URI
import java.net.URL
import java.nio.file.Path

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
