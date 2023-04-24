rootProject.name = "at.asitplus.attestation-backend"

includeBuild("../.."){
    dependencySubstitution {
        substitute(module("at.asitplus:attestation-service"))
    }
}