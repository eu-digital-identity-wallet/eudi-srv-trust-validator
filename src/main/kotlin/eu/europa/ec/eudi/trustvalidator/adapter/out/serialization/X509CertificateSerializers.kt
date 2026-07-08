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
package eu.europa.ec.eudi.trustvalidator.adapter.out.serialization

import arrow.core.NonEmptyList
import arrow.core.serialization.NonEmptyListSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.io.encoding.Base64

object X509CertificateSerializer : KSerializer<X509Certificate> {
    private val base64 by lazy { Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL) }

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("X509Certificate", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: X509Certificate,
    ) {
        val encoded = base64.encode(value.encoded)
        encoder.encodeString(encoded)
    }

    override fun deserialize(decoder: Decoder): X509Certificate {
        val encoded = decoder.decodeString()
        val decoded = base64.decode(encoded)
        return decoded.inputStream().use {
            val factory = CertificateFactory.getInstance("X.509")
            factory.generateCertificate(it) as X509Certificate
        }
    }
}

object X509CertificateChainSerializer : KSerializer<NonEmptyList<X509Certificate>> by NonEmptyListSerializer(
    X509CertificateSerializer,
)
