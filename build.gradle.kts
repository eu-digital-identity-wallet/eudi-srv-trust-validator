import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugin.spring)
    alias(libs.plugins.kotlin.plugin.serialization)
    alias(libs.plugins.spotless)
    alias(libs.plugins.kapt)
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
    implementation(platform(libs.dss.bom))
    implementation(platform(libs.spring.boot.dependencies))

    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlin.reflect)
    implementation(libs.kotlinx.coroutines.reactor)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.datetime)

    implementation(libs.arrow.core)
    implementation(libs.arrow.core.serialization)

    implementation(libs.consultation.dss)
    implementation(libs.dss.tsl.validation)
    implementation(libs.dss.policy.jaxb)
    implementation(libs.dss.utils.google.guava)

    implementation(libs.spring.boot.starter.webflux)
    implementation(libs.spring.boot.starter.security)
    implementation(libs.spring.boot.starter.thymeleaf)
    implementation(libs.spring.boot.starter.actuator)
    implementation(libs.reactor.kotlin.extensions)
    kapt(libs.spring.boot.configuration.processor)

    implementation(libs.webjars.locator.lite)
    implementation(libs.swagger.ui)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.spring.boot.starter.test)
}

kotlin {

    jvmToolchain {
        languageVersion = JavaLanguageVersion.of(libs.versions.java.get())
    }

    compilerOptions {
        apiVersion = KotlinVersion.DEFAULT
        freeCompilerArgs.addAll(
            "-Xjsr305=strict",
        )
        optIn.addAll(
            "kotlinx.serialization.ExperimentalSerializationApi",
            "kotlin.io.encoding.ExperimentalEncodingApi",
            "kotlin.contracts.ExperimentalContracts",
            "kotlin.time.ExperimentalTime",
        )
    }
}

tasks {
    test {
        useJUnitPlatform()
    }
}

springBoot {
    buildInfo()
}

tasks.named<BootBuildImage>("bootBuildImage") {
    imageName.set("$group/${project.name}")
    publish.set(false)
    // get the BP_OCI_* from env, for https://github.com/paketo-buildpacks/image-labels
    // get the BP_JVM_* from env, jlink optimisation
    environment.set(System.getenv())
    val env = environment.get()
    docker {
        publishRegistry {
            env["REGISTRY_URL"]?.let { url = it }
            env["REGISTRY_USERNAME"]?.let { username = it }
            env["REGISTRY_PASSWORD"]?.let { password = it }
        }
        env["DOCKER_METADATA_OUTPUT_TAGS"]?.let { tagStr ->
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
    nvd.apiKey = System.getenv("NVD_API_KEY") ?: properties["nvdApiKey"]?.toString() ?: ""
}
