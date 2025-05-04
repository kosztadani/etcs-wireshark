plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
}

buildscript {
    configurations.classpath {
        resolutionStrategy.activateDependencyLocking()
    }
}
