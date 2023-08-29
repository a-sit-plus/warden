rootProject.name = "attestation-root"


pluginManagement {
    repositories {
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            maven("https://maven.pkg.jetbrains.space/kotlin/p/dokka/dev")
            name = "aspConventions"
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

include("attestation-service")


includeBuild("android-attestation-root"){
    dependencySubstitution {
        substitute(module("at.asitplus:android-attestation")).using(project(":android-attestation"))
    }
}