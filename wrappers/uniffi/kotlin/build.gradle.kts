plugins {
    kotlin("jvm")
}

repositories {
    mavenCentral()
}

group = "equs"
version = "1.0-SNAPSHOT"

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")
    implementation("net.java.dev.jna:jna:5.14.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.0")
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.1")
    // OkHttp MockWebServer for testing
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
}

val fixtureBundleFile = layout.buildDirectory.file("fixtures/fixtures.generated.json")

val fixtureGen = tasks.register<Exec>("fixtureGen") {
    group = "verification"
    description = "Generates the equs-test-fixtures bundle that EQUS_FIXTURE_BUNDLE points test at."
    val outFile = fixtureBundleFile.get().asFile
    doFirst { outFile.parentFile.mkdirs() }
    workingDir(rootDir.parentFile.parentFile.parentFile)
    commandLine(
        "cargo", "run", "-p", "equs-test-fixtures", "--bin", "fixture_gen",
        "--", "--out", outFile.absolutePath,
    )
    outputs.file(outFile)
    outputs.upToDateWhen { false }
}

tasks.test {
    useJUnitPlatform()
    dependsOn(fixtureGen)
    environment("EQUS_FIXTURE_BUNDLE", fixtureBundleFile.get().asFile.absolutePath)
}
kotlin {
    jvmToolchain(17)
}