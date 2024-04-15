rootProject.name = "attestation-root"


pluginManagement {
    repositories {
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

include("attestation-service")

//do not depend on included build for publishing
if (gradle.startParameter.taskNames.find { it.contains("publish") } == null)
    includeBuild("android-attestation-root") {
        dependencySubstitution {
            substitute(module("at.asitplus:android-attestation")).using(project(":android-attestation"))
        }
    }