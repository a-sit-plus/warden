rootProject.name = "WARDEN"
pluginManagement {
    repositories {
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

include("proto")
include("roboto")
include("roboto-diag")
project(":proto").projectDir = file("serverside/proto")
project(":roboto").projectDir = file("serverside/roboto")
project(":roboto-diag").projectDir = file("utils/roboto-diag")



include("supreme-verifier")
include("supreme-common")
include("supreme-client")
project(":supreme-verifier").projectDir = file("supreme/verifier")
project(":supreme-common").projectDir = file("supreme/common")
project(":supreme-client").projectDir = file("supreme/client")