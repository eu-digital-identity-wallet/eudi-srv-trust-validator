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

import eu.europa.ec.eudi.etsi119602.Uri
import eu.europa.ec.eudi.etsi119602.consultation.*
import eu.europa.ec.eudi.etsi119602.consultation.eu.ServiceDigitalIdentityCertificateType
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

private typealias LoteLocations = SupportedLists<Uri>
private typealias LoteServices = SupportedLists<LotEMeta<VerificationContext>>

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
            ProvisionTrustAnchorsFromLoTEs.eudiwJvm(
                loadLoTEAndPointers = LoadLoTEAndPointers(
                    constraints,
                    verifyJwtSignature = { VerifyJwtSignature.Outcome.Verified(it) },
                    LoadSingleLoTEWithFileCache(
                        cacheDirectory = KotlinXPath(cacheDirectory.toString()),
                        downloadSingleLoTE = DownloadSingleLoTE(httpClient),
                        fileCacheExpiration = 24.hours,
                        clock = clock,
                    ),
                ),
                svcTypePerCtx = services,
                continueOnProblem = continueOnProblem,
                pkix = ValidateCertificateChainUsingPKIXJvm { isRevocationEnabled = false },
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
        pidProviders = pidProviders?.lote?.location?.let { Uri(it.toExternalForm()) },
        walletProviders = walletProviders?.lote?.location?.let { Uri(it.toExternalForm()) },
        wrpacProviders = wrpacProviders?.lote?.location?.let { Uri(it.toExternalForm()) },
        wrprcProviders = wrprcProviders?.lote?.location?.let { Uri(it.toExternalForm()) },
        pubEaaProviders = pubEaaProviders?.lote?.location?.let { Uri(it.toExternalForm()) },
        qeaProviders = qeaaProviders?.lote?.location?.let { Uri(it.toExternalForm()) },
        eaaProviders = eaaProviders?.mapNotNull { eaaProvider ->
            eaaProvider.lote?.let {
                eaaProvider.useCase to Uri(it.location.toExternalForm())
            }
        }?.toMap().orEmpty(),
    )

private fun TrustSourcesConfigurationProperties.loteServices(): LoteServices =
    LoteServices(
        pidProviders = pidProviders?.lote?.let {
            LotEMeta(
                mapOf(
                    VerificationContext.PID to LotEMeta.SvcAndEEProfile(
                        Uri(it.issuanceService.toString()),
                        null,
                    ),
                    VerificationContext.PIDStatus to LotEMeta.SvcAndEEProfile(
                        Uri(it.revocationService.toString()),
                        null,
                    ),
                ),
                ServiceDigitalIdentityCertificateType.EndEntityOrCA,
            )
        },
        walletProviders = walletProviders?.lote?.let {
            LotEMeta(
                mapOf(
                    VerificationContext.WalletInstanceAttestation to LotEMeta.SvcAndEEProfile(
                        Uri(it.issuanceService.toString()),
                        null,
                    ),
                    VerificationContext.WalletUnitAttestation to LotEMeta.SvcAndEEProfile(
                        Uri(it.issuanceService.toString()),
                        null,
                    ),
                    VerificationContext.WalletUnitAttestationStatus to LotEMeta.SvcAndEEProfile(
                        Uri(it.revocationService.toString()),
                        null,
                    ),
                ),
                ServiceDigitalIdentityCertificateType.EndEntityOrCA,
            )
        },
        wrpacProviders = wrpacProviders?.lote?.let {
            LotEMeta(
                mapOf(
                    VerificationContext.WalletRelyingPartyAccessCertificate to LotEMeta.SvcAndEEProfile(
                        Uri(it.issuanceService.toString()),
                        null,
                    ),
                ),
                ServiceDigitalIdentityCertificateType.EndEntityOrCA,
            )
        },
        wrprcProviders = wrprcProviders?.lote?.let {
            LotEMeta(
                mapOf(
                    VerificationContext.WalletRelyingPartyRegistrationCertificate to LotEMeta.SvcAndEEProfile(
                        Uri(it.issuanceService.toString()),
                        null,
                    ),
                    VerificationContext.WalletRelyingPartyRegistrationCertificateStatus to LotEMeta.SvcAndEEProfile(
                        Uri(it.revocationService.toString()),
                        null,
                    ),
                ),
                ServiceDigitalIdentityCertificateType.EndEntityOrCA,
            )
        },
        pubEaaProviders = pubEaaProviders?.lote?.let {
            LotEMeta(
                mapOf(
                    VerificationContext.PubEAA to LotEMeta.SvcAndEEProfile(
                        Uri(it.issuanceService.toString()),
                        null,
                    ),
                    VerificationContext.PubEAAStatus to LotEMeta.SvcAndEEProfile(
                        Uri(it.revocationService.toString()),
                        null,
                    ),
                ),
                ServiceDigitalIdentityCertificateType.EndEntityOrCA,
            )
        },
        qeaProviders = qeaaProviders?.lote?.let {
            LotEMeta(
                mapOf(
                    VerificationContext.QEAA to LotEMeta.SvcAndEEProfile(
                        Uri(it.issuanceService.toString()),
                        null,
                    ),
                    VerificationContext.QEAAStatus to LotEMeta.SvcAndEEProfile(
                        Uri(it.revocationService.toString()),
                        null,
                    ),
                ),
                ServiceDigitalIdentityCertificateType.EndEntityOrCA,
            )
        },
        eaaProviders = eaaProviders.orEmpty()
            .mapNotNull { eaaProvider ->
                eaaProvider.lote?.let {
                    eaaProvider.useCase to LotEMeta(
                        mapOf(
                            VerificationContext.EAA(eaaProvider.useCase) to LotEMeta.SvcAndEEProfile(
                                Uri(it.issuanceService.toString()),
                                null,
                            ),
                            VerificationContext.EAAStatus(eaaProvider.useCase) to LotEMeta.SvcAndEEProfile(
                                Uri(it.revocationService.toString()),
                                null,
                            ),
                        ),
                        ServiceDigitalIdentityCertificateType.EndEntityOrCA,
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
    fun info(context: VerificationContext, location: Uri) {
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
