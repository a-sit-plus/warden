rootProject.name = "attestation-service"

includeBuild("android-attestation-root"){
    dependencySubstitution {
        substitute(module("at.asitplus:android-attestation")).using(project(":android-attestation"))
    }
}