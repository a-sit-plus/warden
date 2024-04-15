import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.datetime
import org.gradle.kotlin.dsl.support.listFilesOrdered

plugins {
    kotlin("jvm")
    id("org.jetbrains.dokka")
    id("maven-publish")
    id("signing")
    id("at.asitplus.gradle.conventions")
}

group = "at.asitplus"
val artifactVersion: String by extra
val androidAttestationVersion: String by extra
version = artifactVersion

sourceSets.test {
    kotlin {
        srcDir("../android-attestation-root/android-attestation/src/test/kotlin/data")
    }
}

dependencies {
    api("at.asitplus:android-attestation:$androidAttestationVersion")
    api(datetime())
    implementation("ch.veehait.devicecheck:devicecheck-appattest:0.9.6")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:2.14.2")
    implementation("net.swiftzer.semver:semver:1.2.0")
    implementation(bouncycastle("bcpkix", "jdk18on"))
    implementation("org.slf4j:slf4j-api:1.7.36")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.14.2")

    testImplementation("org.slf4j:slf4j-reload4j:1.7.36")
    testImplementation(kotlin("reflect"))
}


//No, it's not pretty! Yes it's fragile! But it also works perfectly well when run from a GitHub actions and that's what counts
tasks.dokkaHtml {

    val moduleDesc = File("$rootDir/dokka-tmp.md").also { it.createNewFile() }
    val readme =
        File("${rootDir}/README.md").readText().replaceFirst("# ", "")
    val moduleTitle = readme.lines().first()
    moduleDesc.writeText("# Module $readme")
    moduleName.set(moduleTitle)

    dokkaSourceSets {
        named("main") {

            includes.from(moduleDesc)
        }
    }
    outputDirectory.set(file("${rootDir}/docs"))
    doLast {
        rootDir.listFilesOrdered { it.extension.lowercase() == "png" || it.extension.lowercase() == "svg" }
            .forEach { it.copyTo(File("$rootDir/docs/${it.name}"), overwrite = true) }
    }
}
val deleteDokkaOutputDir by tasks.register<Delete>("deleteDokkaOutputDirectory") {
    delete(tasks.dokkaHtml.get().outputDirectory.get())
}

val javadocJar: TaskProvider<Jar> by tasks.registering(Jar::class) {
    dependsOn(deleteDokkaOutputDir, tasks.dokkaHtml)
    archiveClassifier.set("javadoc")
    from(tasks.dokkaHtml.get().outputDirectory)
}
val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allSource)
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


signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications["mavenJava"])
}
