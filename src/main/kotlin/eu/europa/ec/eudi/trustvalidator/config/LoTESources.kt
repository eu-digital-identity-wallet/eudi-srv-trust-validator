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

import eu.europa.ec.eudi.etsi119602.URI
import eu.europa.ec.eudi.etsi119602.consultation.*
import eu.europa.ec.eudi.etsi119602.x509Certificate
import eu.europa.ec.eudi.etsi1196x2.consultation.*
import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import java.nio.file.Path as JavaPath
import kotlinx.io.files.Path as KotlinXPath

private val log = LoggerFactory.getLogger("getTrustAnchorsUsingLoTE")

private typealias LoteLocations = SupportedLists<URI>
private typealias LoteServices = SupportedLists<LotEMata<VerificationContext, X509Certificate>>

fun TrustSourcesConfigurationProperties.isChainTrustedForContextUsingLoTE(
    scope: DisposableScope,
    cacheDirectory: JavaPath,
    httpClient: HttpClient,
    clock: Clock,
    continueOnProblem: ContinueOnProblem = ContinueOnProblem.Never,
    constraints: LoadLoTEAndPointers.Constraints,
): ComposeChainTrust<List<X509Certificate>, VerificationContext, TrustAnchor>? =
    loteSources()?.let { (locations, services) ->
        log.info(locations)
        val provisionTrustAnchorsFromLOTE =
            ProvisionTrustAnchorsFromLoTEs(
                LoadLoTEAndPointers(
                    constraints,
                    verifyJwtSignature = { VerifyJwtSignature.Outcome.Verified(it) },
                    LoadSingleLoTEWithFileCache(
                        cacheDirectory = KotlinXPath(cacheDirectory.toString()),
                        downloadSingleLoTE = DownloadSingleLoTE(httpClient),
                        fileCacheExpiration = 24.hours,
                        clock = clock,
                    ),
                ),
                createTrustAnchors = { serviceDigitalIdentity ->
                    serviceDigitalIdentity.x509Certificates.orEmpty().map { TrustAnchor(it.x509Certificate(), null) }
                },
                extractCertificate = { it.trustedCert },
                getCertInfo = { "Info[subject=${it.subjectX500Principal}-sn=${it.serialNumber}]" },
                ValidateCertificateChainUsingDirectTrustJvm,
                ValidateCertificateChainUsingPKIXJvm { isRevocationEnabled = false },
                continueOnProblem,
                services,
            )

        provisionTrustAnchorsFromLOTE.cached(scope, locations, ttl = 10.minutes)
    }

private fun TrustSourcesConfigurationProperties.loteSources(): Pair<LoteLocations, LoteServices>? {
    val loteLocations = loteLocations()
    val loteServices = loteServices()
    return if (!loteLocations.isEmpty() && !loteServices.isEmpty()) (loteLocations to loteServices) else null
}

private fun TrustSourcesConfigurationProperties.loteLocations(): LoteLocations =
    LoteLocations(
        pidProviders = pidProviders?.lote?.location?.toExternalForm(),
        walletProviders = walletProviders?.lote?.location?.toExternalForm(),
        wrpacProviders = wrpacProviders?.lote?.location?.toExternalForm(),
        wrprcProviders = wrprcProviders?.lote?.location?.toExternalForm(),
        pubEaaProviders = pubEaaProviders?.lote?.location?.toExternalForm(),
        qeaProviders = qeaaProviders?.lote?.location?.toExternalForm(),
        eaaProviders = eaaProviders?.mapNotNull { eaaProvider ->
            eaaProvider.lote?.let {
                eaaProvider.useCase to it.location.toExternalForm()
            }
        }?.toMap().orEmpty(),
    )

private fun TrustSourcesConfigurationProperties.loteServices(): LoteServices =
    LoteServices(
        pidProviders = pidProviders?.lote?.let {
            LotEMata(
                mapOf(
                    VerificationContext.PID to it.issuanceService.toString(),
                    VerificationContext.PIDStatus to it.revocationService.toString(),
                ),
                true,
                null,
            )
        },
        walletProviders = walletProviders?.lote?.let {
            LotEMata(
                mapOf(
                    VerificationContext.WalletInstanceAttestation to it.issuanceService.toString(),
                    VerificationContext.WalletUnitAttestation to it.issuanceService.toString(),
                    VerificationContext.WalletUnitAttestationStatus to it.revocationService.toString(),
                ),
                true,
                null,
            )
        },
        wrpacProviders = wrpacProviders?.lote?.let {
            LotEMata(
                mapOf(
                    VerificationContext.WalletRelyingPartyAccessCertificate to it.issuanceService.toString(),
                ),
                false,
                null,
            )
        },
        wrprcProviders = wrprcProviders?.lote?.let {
            LotEMata(
                mapOf(
                    VerificationContext.WalletRelyingPartyRegistrationCertificate to it.issuanceService.toString(),
                ),
                false,
                null,
            )
        },
        pubEaaProviders = pubEaaProviders?.lote?.let {
            LotEMata(
                mapOf(
                    VerificationContext.PubEAA to it.issuanceService.toString(),
                    VerificationContext.PubEAAStatus to it.revocationService.toString(),
                ),
                true,
                null,
            )
        },
        qeaProviders = qeaaProviders?.lote?.let {
            LotEMata(
                mapOf(
                    VerificationContext.QEAA to it.issuanceService.toString(),
                    VerificationContext.QEAAStatus to it.revocationService.toString(),
                ),
                true,
                null,
            )
        },
        eaaProviders = eaaProviders.orEmpty()
            .mapNotNull { eaaProvider ->
                eaaProvider.lote?.let {
                    eaaProvider.useCase to LotEMata<VerificationContext, X509Certificate>(
                        mapOf(
                            VerificationContext.EAA(eaaProvider.useCase) to it.issuanceService.toString(),
                            VerificationContext.EAAStatus(eaaProvider.useCase) to it.revocationService.toString(),
                        ),
                        true,
                        null,
                    )
                }
            }.toMap(),
    )

private fun SupportedLists<*>.isEmpty(): Boolean =
    null == pidProviders &&
        null == walletProviders &&
        null == wrpacProviders &&
        null == wrprcProviders &&
        null == pubEaaProviders &&
        null == qeaProviders &&
        eaaProviders.isEmpty()

private fun Logger.info(locations: LoteLocations) {
    fun info(context: VerificationContext, location: String) {
        info("Configured VerificationContext $context using LoTE $location")
    }

    locations.pidProviders?.let {
        info(VerificationContext.PID, it)
        info(VerificationContext.PIDStatus, it)
    }
    locations.walletProviders?.let {
        info(VerificationContext.WalletInstanceAttestation, it)
        info(VerificationContext.WalletUnitAttestation, it)
        info(VerificationContext.WalletUnitAttestationStatus, it)
    }
    locations.wrpacProviders?.let {
        info(VerificationContext.WalletRelyingPartyAccessCertificate, it)
    }
    locations.wrprcProviders?.let {
        info(VerificationContext.WalletRelyingPartyRegistrationCertificate, it)
    }
    locations.pubEaaProviders?.let {
        info(VerificationContext.PubEAA, it)
        info(VerificationContext.PubEAAStatus, it)
    }
    locations.qeaProviders?.let {
        info(VerificationContext.QEAA, it)
        info(VerificationContext.QEAAStatus, it)
    }
    if (!locations.eaaProviders.isEmpty()) {
        locations.eaaProviders.forEach { (useCase, location) ->
            info(VerificationContext.EAA(useCase), location)
            info(VerificationContext.EAAStatus(useCase), location)
        }
    }
}
