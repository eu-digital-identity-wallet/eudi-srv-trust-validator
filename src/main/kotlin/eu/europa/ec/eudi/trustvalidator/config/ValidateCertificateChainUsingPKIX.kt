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

import eu.europa.ec.eudi.etsi1196x2.consultation.JvmSecurity
import eu.europa.ec.eudi.etsi1196x2.consultation.ValidateCertificateChainUsingPKIX
import eu.europa.ec.eudi.etsi1196x2.consultation.ValidateCertificateChainUsingPKIXJvm
import java.security.cert.PKIXRevocationChecker
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.*

fun ValidateCertificateChainUsingPKIX(isRevocationEnable: Boolean): ValidateCertificateChainUsingPKIX<List<X509Certificate>, TrustAnchor> {
    if (!isRevocationEnable)
        return ValidateCertificateChainUsingPKIXJvm {
            this.isRevocationEnabled = false
        }
    return ValidateCertificateChainUsingPKIXJvm {
        isRevocationEnabled = true
        addCertPathChecker(
            checkNotNull(
                JvmSecurity.DefaultPKIXValidator.revocationChecker as? PKIXRevocationChecker,
            ).apply {
                options = EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS)
            },
        )
    }
}
