plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val kotestVer = System.getenv("KOTEST_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotest.get()
    val kspVer = System.getenv("KSP_VERSION_ENV")?.ifBlank { null } ?: "$kotlinVer-${libs.versions.ksp.get()}"
    id("io.kotest") version kotestVer apply false //we're JVM-only so apply false. but we need the plugin in the classpath until I clean up the conventions plugins
    kotlin("jvm") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("at.asitplus.gradle.conventions") version "20250729"
    id("com.google.devtools.ksp") version kspVer
    id("com.android.library") version "8.10.0" apply (false)
}

val artifactVersion: String by extra
val groupId: String by extra
group = groupId
version = artifactVersion
