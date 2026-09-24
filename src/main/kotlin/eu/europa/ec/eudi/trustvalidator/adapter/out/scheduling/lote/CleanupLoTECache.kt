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
package eu.europa.ec.eudi.trustvalidator.adapter.out.scheduling.lote

import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.SchedulingConfigurer
import org.springframework.scheduling.config.IntervalTask
import org.springframework.scheduling.config.ScheduledTaskRegistrar
import java.nio.file.Path
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

private val log = LoggerFactory.getLogger(CleanupLoTECache::class.java)

class CleanupLoTECache(
    private val location: Path,
    private val interval: Duration,
) : SchedulingConfigurer {
    override fun configureTasks(taskRegistrar: ScheduledTaskRegistrar) {
        taskRegistrar.addFixedRateTask(interval = interval, initialDelay = 0.seconds) {
            log.info("Cleaning up LoTE cache at $location...")
            location.toFile().deleteRecursively()
        }
    }
}

private fun ScheduledTaskRegistrar.addFixedRateTask(
    interval: Duration,
    initialDelay: Duration,
    task: Runnable,
) {
    addFixedRateTask(IntervalTask(task, interval.toJavaDuration(), initialDelay.toJavaDuration()))
}
