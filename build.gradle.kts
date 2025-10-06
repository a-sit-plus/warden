plugins {
    id("io.kotest.multiplatform") version libs.versions.kotest.get() apply false //we're JVM-only so apply false. but we need the plugin in the classpath until I clean up the conventions plugins
    kotlin("jvm") version (System.getenv("KOTLIN_VERSION_ENV")?.let { it.ifBlank { null } }
        ?: libs.versions.kotlin.get()) apply false
    kotlin("plugin.serialization") version (System.getenv("KOTLIN_VERSION_ENV")?.let { it.ifBlank { null } }
        ?: libs.versions.kotlin.get()) apply false
    id("at.asitplus.gradle.conventions") version "20250729"
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion
