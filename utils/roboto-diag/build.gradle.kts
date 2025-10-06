
group = "at.asitplus"
version = "0.0.3"

plugins {
    kotlin("jvm")
    application
    id("at.asitplus.gradle.conventions")
    id("com.gradleup.shadow")
}

application {
    mainClass.set("at.asitplus.attestation.android.DiagKt")
}

sourceSets.main {
    java {
        srcDirs("${project.rootDir}dependencies/android-key-attestation/src/main/java")

        exclude(
            "com/android/example/",
            "com/google/android/attestation/CertificateRevocationStatus.java",
        )
        File("${project.rootDir}/dependencies/android-key-attestation/src/main/java/com/google/android/attestation/AuthorizationList.java").let {
            if (it.exists()) {
                it.renameTo(File(it.canonicalPath + ".bak"))
            }
        }
    }
}


dependencies {
    implementation(project(":roboto"))
    implementation("com.google.auto.value:auto-value-annotations:1.11.0")
    implementation("com.google.code.gson:gson:2.12.1")
    implementation("at.asitplus.signum:indispensable:3.16.3") {
        exclude("org.bouncycastle", "bcpkix-jdk18on")
    }
}
