plugins {
    id("dev.kosztadani.etcs_wireshark.application")
}

// The "ucanaccess" library is an "automatic" module, but Gradle doesn't seem
// to offer direct support for that.
tasks.named<JavaCompile>("compileJava") {
    options.compilerArgs.addAll(
        listOf(
            "--module-path", classpath.asPath
        )
    )
}
tasks.named<Javadoc>("javadoc") {
    options.modulePath(classpath.files.toList())
}

val applicationMainClass = "dev.kosztadani.etcs_wireshark.mdb_to_pcapng.MdbToPcapngMain"

application {
    mainClass.set(applicationMainClass)
}

tasks.jar {
    manifest {
        attributes(
            mapOf("Main-Class" to applicationMainClass)
        )
    }
}

dependencies {
    implementation(libs.ucanaccess)
}
