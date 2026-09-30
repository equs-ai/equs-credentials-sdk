plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
    id("signing")
}

val baseVersion = "1.0.1"
val environment = project.findProperty("env")?.toString()

group = "ai.equs.credentials"
val ciTag: String? = System.getenv("CI_COMMIT_TAG")?.takeIf { it.isNotBlank() }
version = ciTag ?: if (environment == "development") "$baseVersion-dev" else baseVersion

val mavenRepoUrl: String? = System.getenv("REGISTRY_URL_MAVEN")
val signingKey: String? = project.findProperty("signingKey")?.toString()?.takeIf { it.isNotBlank() }

val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
}

publishing {
	publications {
		create<MavenPublication>("release") {
			afterEvaluate { from(components["release"]) }
			artifact(javadocJar)

			groupId = group.toString()
			artifactId = "equs-credentials-sdk"
			version = project.version.toString()

			pom {
				name.set("EQUS Credentials SDK for Android")
				description.set("Kotlin bindings for the EQUS Credentials SDK, a Rust SDK implementing multiple decentralized identity protocols")
				url.set("https://github.com/equs-ai/equs-credentials-sdk")
				licenses {
					license {
						name.set("Apache-2.0")
						url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
					}
				}
				developers {
					developer {
						id.set("equs-ai")
						name.set("Equs")
						url.set("https://github.com/equs-ai")
					}
				}
				scm {
					url.set("https://github.com/equs-ai/equs-credentials-sdk")
					connection.set("scm:git:https://github.com/equs-ai/equs-credentials-sdk.git")
					developerConnection.set("scm:git:ssh://git@github.com/equs-ai/equs-credentials-sdk.git")
				}
			}
		}
	}

	repositories {
		maven {
			name = "staging"
			url = uri(layout.buildDirectory.dir("staging"))
		}
		if (mavenRepoUrl != null) {
			maven {
				url = uri(mavenRepoUrl)

				credentials {
					username = "gitlab-ci-token"
					password = System.getenv("CI_JOB_TOKEN")
				}
			}
		}
	}
}

signing {
	isRequired = signingKey != null
	if (signingKey != null) {
		useInMemoryPgpKeys(signingKey, project.findProperty("signingPassword")?.toString() ?: "")
		sign(publishing.publications["release"])
	}
}


android {
    namespace = "com.equs.credentials"
    compileSdk = 33

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    sourceSets {
        getByName("main").java.srcDirs("src/main/kotlin")
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

repositories {
    google()
    mavenCentral()
}

dependencies {
    api("net.java.dev.jna:jna:5.13.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")
}
