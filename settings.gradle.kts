rootProject.name = "attestation-service"

includeBuild("android-attestation"){
    dependencySubstitution {
        substitute(module("at.asitplus:android-attestation"))
    }
}