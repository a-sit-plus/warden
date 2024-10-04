plugins {  id("at.asitplus.gradle.conventions") version "2.0.20+20240920" }

group = "at.asitplus"

//work around nexus publish bug
val artifactVersion: String by extra
version = artifactVersion
//end work around nexus publish bug
