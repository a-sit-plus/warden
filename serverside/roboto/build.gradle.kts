import at.asitplus.gradle.AspVersions
import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.datetime
import at.asitplus.gradle.ktor
import org.gradle.kotlin.dsl.support.listFilesOrdered
import org.jetbrains.kotlin.gradle.targets.js.testing.karma.processKarmaStackTrace

group = "at.asitplus"
val artifactVersion: String by extra
version = artifactVersion

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("maven-publish")
    id("org.jetbrains.dokka")
    id("signing")
    id("at.asitplus.gradle.conventions")
}

sourceSets.main {
    java {
        srcDirs("${project.rootDir}/dependencies/android-key-attestation/src/main/java",
            "${project.rootDir}/dependencies/keyattestation/src/main/kotlin/")


        exclude(
            "com/android/example/",
            "com/google/android/attestation/CertificateRevocationStatus.java",
            "testing"
        )
        File("${project.rootDir}/dependencies/android-key-attestation/src/main/java/com/google/android/attestation/AuthorizationList.java").let {
            if (it.exists()) {
               it.delete()
            }
        }
    }
}

sourceSets.test {
    /* cursed workaround for including this very same source directory in another project when using this project
    for composite builds */
    kotlin {
        srcDir("src/test/kotlin/data")
    }
    java {
        srcDirs("${project.rootDir}/dependencies/http-proxy/src/main/java")
    }
    resources {
        srcDirs(
            rootProject.layout.projectDirectory.dir("dependencies").dir("android-key-attestation").dir("src").dir("test")
                .dir("resources"),
            "src/test/resources"
        )
    }
}


dependencies {
    api(bouncycastle("bcpkix", "jdk18on"))
    implementation(ktor("client-core"))
    implementation(ktor("client-content-negotiation"))
    implementation(ktor("serialization-kotlinx-json"))
    implementation(ktor("client-cio"))

    api("com.google.guava:guava:33.4.0-jre")
    implementation("com.google.auto.value:auto-value-annotations:1.11.0")
    annotationProcessor("com.google.auto.value:auto-value:1.11.0")
    api("com.google.protobuf:protobuf-javalite:4.29.3")
    api("at.asitplus.signum:indispensable:3.17.0")  {
        exclude("org.bouncycastle", "bcpkix-jdk18on")
    }


    //dependencies for new attestation lib
    implementation("co.nstant.in:cbor:0.9")
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("com.google.errorprone:error_prone_annotations:2.41.0")
    implementation("com.google.protobuf:protobuf-javalite:4.28.3")
    implementation("com.google.protobuf:protobuf-kotlin-lite:4.28.3")

    testImplementation("org.slf4j:slf4j-reload4j:1.7.36")
    testImplementation("io.netty:netty-all:4.1.36.Final")
    testImplementation("commons-cli:commons-cli:1.4")
    testImplementation("ch.qos.logback:logback-classic:1.2.3")
    testImplementation("ch.qos.logback:logback-access:1.2.3")
    testImplementation(ktor("client-mock"))
    testImplementation(datetime())
}


tasks.test {
    useJUnitPlatform()
}

//No, it's not pretty! Yes it's fragile! But it also works perfectly well when run from a GitHub actions and that's what counts
tasks.dokkaHtml {

    val moduleDesc = File("$rootDir/dokka-tmp.md").also { it.createNewFile() }
    val readme =
        File("${rootDir}/README.md").readText()
    moduleDesc.writeText("# Module ${project.name}\n\n$readme")
    moduleName.set(project.name)

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
            if (this.name != "relocation") artifact(sourcesJar.get())
            if (this.name != "relocation") artifact(javadocJar.get())
            pom {
                name.set("WARDEN-roboto")
                description.set("Server-Side Android Attestation Library")
                url.set("https://github.com/a-sit-plus/warden-roboto")
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
                    connection.set("scm:git:git@github.com:a-sit-plus/warden-roboto.git")
                    developerConnection.set("scm:git:git@github.com:a-sit-plus/warden-roboto.git")
                    url.set("https://github.com/a-sit-plus/warden-roboto")
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
    sign(publishing.publications)
}
