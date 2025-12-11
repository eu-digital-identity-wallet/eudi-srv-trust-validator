/*
 * Copyright (c) 2023 European Commission
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
@file:UseSerializers(NonEmptyListSerializer::class)

package eu.europa.ec.eudi.trustvalidator.domain

import arrow.core.Ior
import arrow.core.serialization.NonEmptyListSerializer
import kotlinx.serialization.UseSerializers
import java.net.URL
import java.security.KeyStore

/**
 * Validator configuration options
 */
data class ValidatorConfig(
    val trustSourcesConfig: Map<ServiceType, TrustSourceConfig>,
)

typealias TrustSourceConfig = Ior<TrustedListConfig, KeyStoreConfig>

enum class ServiceType(val value: String) {
    PIDProvider("http://uri.etsi.org/Svc/Svctype/Provider/PID"),
    QEAAProvider("http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"),
    PubEAAProvider("http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA"),
    WalletProvider("http://uri.etsi.org/TrstSvc/Svctype/Provider/Wallet"), // TODO TBD
}

data class TrustedListConfig(
    val location: URL,
    val serviceTypeFilter: ServiceType?,
    val refreshInterval: String = "0 0 * * * *",
    val keystoreConfig: KeyStoreConfig?,
)

data class KeyStoreConfig(
    val keystorePath: String,
    val keystoreType: String? = "JKS",
    val keystorePassword: CharArray? = "".toCharArray(),
    val keystore: KeyStore,
)

fun trustSourcesConfig(trustedList: TrustedListConfig?, keystore: KeyStoreConfig?): Ior<TrustedListConfig, KeyStoreConfig> =
    Ior.fromNullables(trustedList, keystore) ?: error("Either trustedList or keystore must be provided")
