import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.io.FileInputStream
import java.util.*

Properties().apply {
    kotlin.runCatching { load(FileInputStream(project.rootProject.file("local.properties"))) }
    forEach { (k, v) -> extra.set(k as String, v) }
}

plugins {
    kotlin("jvm") version "1.8.20"
    id("org.jetbrains.dokka") version "1.7.20"
    id("maven-publish")
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
    id("signing")
}

group = "at.asitplus"
version = "0.5.0"

sourceSets.test {
    kotlin {
        srcDir("android-attestation/src/test/kotlin/data")
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-datetime-jvm:0.4.0")
    implementation("ch.veehait.devicecheck:devicecheck-appattest:0.9.6")
    api("at.asitplus:android-attestation:0.8.2")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:2.14.2")
    implementation("net.swiftzer.semver:semver:1.2.0")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.73")
    implementation("org.slf4j:slf4j-api:1.7.36")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.14.2")

    testImplementation("io.kotest:kotest-runner-junit5:5.5.4")
    testImplementation("io.kotest:kotest-framework-datatest:5.5.4")
    testImplementation("org.slf4j:slf4j-reload4j:1.7.36")
}


tasks.test {
    useJUnitPlatform()
}


val dokkaHtml by tasks.getting(org.jetbrains.dokka.gradle.DokkaTask::class)

val javadocJar: TaskProvider<Jar> by tasks.registering(Jar::class) {
    dependsOn(dokkaHtml)
    archiveClassifier.set("javadoc")
    from(dokkaHtml.outputDirectory)
}

val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allSource)
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "11"
}

repositories {
    mavenCentral()
}

publishing {
    publications {
        register("mavenJava", MavenPublication::class) {
            from(components["java"])
            artifact(sourcesJar.get())
            artifact(javadocJar.get())
            pom {
                name.set("Attestation Service")
                description.set("Server-Side Android+iOS attestation library")
                url.set("https://github.com/a-sit-plus/attestation-service")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("JesusMcCloud")
                        name.set("Bernd Prünster")
                        email.set("bernd.pruenster@a-sit.at")
                    }
                    developer {
                        id.set("nodh")
                        name.set("Christian Kollmann")
                        email.set("christian.kollmann@a-sit.at")
                    }
                }
                scm {
                    connection.set("scm:git:git@github.com:a-sit-plus/attestation-service.git")
                    developerConnection.set("scm:git:git@github.com:a-sit-plus/attestation-service.git")
                    url.set("https://github.com/a-sit-plus/attestation-service")
                }
            }
        }
    }
}


nexusPublishing {
    repositories {
        sonatype() {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
        }
    }
}

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications["mavenJava"])
}