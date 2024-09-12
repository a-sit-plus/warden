rootProject.name = "WARDEN-root"
pluginManagement {
    repositories {
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots") //KOTEST snapshot
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

include("warden")

//do not depend on included build for publishing
if (gradle.startParameter.taskNames.find { it.contains("publish") } == null)
    includeBuild("warden-roboto") {
        dependencySubstitution {
            substitute(module("at.asitplus:warden-roboto")).using(project(":warden-roboto"))
        }
    }