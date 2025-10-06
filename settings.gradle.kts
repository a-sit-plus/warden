rootProject.name = "WARDEN"
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

include("combinato")
include("roboto")
include("roboto-diag")
project(":combinato").projectDir = file("serverside/combinato")
project(":roboto").projectDir = file("serverside/roboto")
project(":roboto-diag").projectDir = file("utils/roboto-diag")
