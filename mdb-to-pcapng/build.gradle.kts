plugins {
    id("dev.kosztadani.etcs_wireshark.application")
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
}
