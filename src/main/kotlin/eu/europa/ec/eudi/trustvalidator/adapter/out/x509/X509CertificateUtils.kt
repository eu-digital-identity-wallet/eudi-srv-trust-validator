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
package eu.europa.ec.eudi.trustvalidator.adapter.out.x509

import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.io.encoding.Base64

object X509CertificateUtils {
    private val certificateFactory by lazy { CertificateFactory.getInstance("X.509") }
    private val base64 by lazy { Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL) }

    fun decodeBase64EncodedDer(encodedCertificate: String): X509Certificate {
        val derEncodedCertificate = base64.decode(encodedCertificate)
        return decodeDer(derEncodedCertificate)
    }

    fun decodeDer(der: ByteArray): X509Certificate = der.inputStream()
        .use {
            certificateFactory.generateCertificate(it) as X509Certificate
        }

    fun base64Encode(certificate: X509Certificate): String = base64.encode(certificate.encoded)
}
