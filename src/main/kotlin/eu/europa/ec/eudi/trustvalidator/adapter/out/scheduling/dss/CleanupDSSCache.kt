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
package eu.europa.ec.eudi.trustvalidator.adapter.out.scheduling.dss

import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.SchedulingConfigurer
import org.springframework.scheduling.config.IntervalTask
import org.springframework.scheduling.config.ScheduledTaskRegistrar
import java.nio.file.Path
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

private val log = LoggerFactory.getLogger(CleanupDSSCache::class.java)

class CleanupDSSCache(private val location: Path) : SchedulingConfigurer {

    override fun configureTasks(taskRegistrar: ScheduledTaskRegistrar) {
        taskRegistrar.addFixedRateTask(interval = 24.hours - 5.minutes, initialDelay = 0.seconds) {
            log.info("Cleaning up DSS cache at $location...")
            location.toFile().deleteRecursively()
        }
    }
}

private fun ScheduledTaskRegistrar.addFixedRateTask(interval: Duration, initialDelay: Duration, task: Runnable) {
    addFixedRateTask(IntervalTask(task, interval.toJavaDuration(), initialDelay.toJavaDuration()))
}
