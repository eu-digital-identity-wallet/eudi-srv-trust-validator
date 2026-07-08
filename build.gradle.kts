import org.jetbrains.kotlin.gradle.dsl.JvmDefaultMode
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugin.spring)
    alias(libs.plugins.kotlin.plugin.serialization)
    alias(libs.plugins.spotless)
    alias(libs.plugins.kover)
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.dependencycheck)
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform(libs.kotlin.bom))
    implementation(platform(libs.kotlinx.serialization.bom))
    implementation(platform(libs.kotlinx.coroutines.bom))
    implementation(platform(libs.arrow.stack))
    implementation(platform(libs.ktor.bom))
    implementation(platform(libs.spring.boot.dependencies))

    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlin.reflect)
    implementation(libs.kotlinx.coroutines.reactor)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.datetime)

    implementation(libs.arrow.core)
    implementation(libs.arrow.core.serialization)

    implementation(libs.ktor.client.cio)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)

    implementation(libs.consultation.lotl)
    implementation(libs.dss.tsl.validation)
    implementation(libs.dss.policy.jaxb)
    implementation(libs.dss.utils.google.guava)
    implementation(libs.consultation.lote)

    implementation(libs.spring.boot.starter.webflux)
    implementation(libs.spring.boot.starter.security)
    implementation(libs.spring.boot.starter.thymeleaf)
    implementation(libs.spring.boot.starter.actuator)
    implementation(libs.reactor.kotlin.extensions)

    implementation(libs.webjars.locator.lite)
    implementation(libs.swagger.ui)
    implementation(libs.bootstrap)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.spring.boot.starter.test)
}

kotlin {
    jvmToolchain {
        languageVersion = JavaLanguageVersion.of(libs.versions.java.get())
        vendor = JvmVendorSpec.ADOPTIUM
        implementation = JvmImplementation.VENDOR_SPECIFIC
    }

    target {
        compilerOptions {
            javaParameters = true
            jvmDefault = JvmDefaultMode.ENABLE
            jvmTarget = JvmTarget.fromTarget(libs.versions.java.get())
            apiVersion = KotlinVersion.DEFAULT
            languageVersion = KotlinVersion.DEFAULT
            freeCompilerArgs.addAll(
                "-Xjsr305=strict",
                "-Xconsistent-data-class-copy-visibility",
            )
        }
    }
}

tasks.test {
    useJUnitPlatform()
}

springBoot {
    buildInfo()
}

tasks.named<BootBuildImage>("bootBuildImage") {
    imageName = "$group/${project.name}"
    publish = false
    environment = System.getenv()

    docker {
        val environment = environment.get()
        publishRegistry {
            environment["REGISTRY_URL"]?.let { url = it }
            environment["REGISTRY_USERNAME"]?.let { username = it }
            environment["REGISTRY_PASSWORD"]?.let { password = it }
        }
        environment["DOCKER_METADATA_OUTPUT_TAGS"]?.let { tagStr ->
            tags = tagStr.split(delimiters = arrayOf("\n", " ")).onEach { println("Tag: $it") }
        }
    }
}

spotless {
    val ktlintVersion = libs.versions.ktlint.get()

    kotlin {
        ktlint(ktlintVersion)
        licenseHeaderFile("FileHeader.txt")
    }

    kotlinGradle {
        ktlint(ktlintVersion)
    }
}

dependencyCheck {
    formats = mutableListOf("XML", "HTML")
    nvd {
        apiKey = System.getenv("NVD_API_KEY") ?: findProperty("nvdApiKey")?.toString() ?: ""
        delay = 10000
        maxRetryCount = 2
    }
}
