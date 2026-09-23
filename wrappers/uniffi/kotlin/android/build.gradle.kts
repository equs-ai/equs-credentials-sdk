plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

val baseVersion = "1.13.1"
val environment = project.findProperty("env")?.toString()

group = "equs"
val ciTag: String? = System.getenv("CI_COMMIT_TAG")?.takeIf { it.isNotBlank() }
version = ciTag ?: if (environment == "development") "$baseVersion-dev" else baseVersion

val mavenRepoUrl: String? = System.getenv("REGISTRY_URL_MAVEN")

publishing {
	publications {
		create<MavenPublication>("release") {
			artifact("build/outputs/aar/android-release.aar") {
				extension = "aar"
			}

			groupId = group.toString()
			artifactId = "equs-credentials-sdk-android"
			version = project.version.toString()
		}
	}

	repositories {
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
}

repositories {
    google()
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.13.0@aar")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")
}
