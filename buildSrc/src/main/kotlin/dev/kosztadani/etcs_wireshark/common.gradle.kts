package dev.kosztadani.etcs_wireshark

import org.gradle.api.tasks.testing.logging.TestLogEvent.*

plugins {
    java
    distribution
    checkstyle
}

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    withSourcesJar()
    withJavadocJar()
}

checkstyle {
    sourceSets = listOf(
        project.sourceSets.main.get(),
        project.sourceSets.test.get(),
    )
}

tasks.named<Checkstyle>("checkstyleMain") {
    configFile = project.rootProject.layout.projectDirectory
        .dir("config")
        .dir("checkstyle")
        .file("checkstyle-main.xml")
        .asFile
}

tasks.named<Checkstyle>("checkstyleTest") {
    configFile = project.rootProject.layout.projectDirectory
        .dir("config")
        .dir("checkstyle")
        .file("checkstyle-test.xml")
        .asFile
}

dependencyLocking {
    lockAllConfigurations()
    lockMode = LockMode.STRICT
}

dependencies {
    versionCatalogs.named("libs").findBundle("testLibraries").ifPresentOrElse(
        {
            testImplementation(it)
        },
        {
            throw AssertionError("Bundle 'testLibraries' not found in libs.versions.toml")
        }
    )
}

tasks.named<Test>("test") {
    useJUnitPlatform()
    testLogging {
        events(PASSED, SKIPPED, FAILED)
    }
}
