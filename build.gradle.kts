plugins {  id("at.asitplus.gradle.conventions") version "2.1.20+20250409" }

group = "at.asitplus"

//work around nexus publish bug
val artifactVersion: String by extra
version = artifactVersion
//end work around nexus publish bug
