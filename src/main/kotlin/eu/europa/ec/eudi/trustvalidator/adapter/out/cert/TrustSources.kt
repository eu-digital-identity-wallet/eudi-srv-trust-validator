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
package eu.europa.ec.eudi.trustvalidator.adapter.out.cert

import eu.europa.ec.eudi.trustvalidator.domain.ServiceType
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.cert.X509Certificate

/**
 * Functional interface for providing the appropriate X5CShouldBe trust source based on trust provider type.
 */
fun interface ProvideTrustSource {
    suspend operator fun invoke(type: String): List<X509Certificate>?
}

class TrustSources(
    private val certsPerType: MutableMap<ServiceType, List<X509Certificate>> = mutableMapOf(),
) : ProvideTrustSource {

    private val mutex = Mutex()

    suspend fun updateWithX5CShouldBe(pattern: ServiceType, certs: List<X509Certificate>) {
        mutex.withLock {
            certsPerType[pattern] = certs
        }
    }

    /**
     * Implementation of TrustSourceProvider
     * Retrieves the X5CShouldBe for the given document type.
     */
    override suspend fun invoke(type: String): List<X509Certificate>? =
        mutex.withLock {
            certsPerType.entries
                .firstOrNull { (pattern, _) -> pattern.value == type }
                ?.value
        }
}
