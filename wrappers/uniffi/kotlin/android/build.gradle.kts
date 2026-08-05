plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

val baseVersion = "1.11.0"
val environment = project.findProperty("env")?.toString()

group = "equstng"
version = if (environment == "development") "$baseVersion-dev" else baseVersion

val ciServerHost = System.getenv("CI_SERVER_HOST")
val ciProjectId = System.getenv("CI_PROJECT_ID")

val mavenRepoUrl = if (ciServerHost != null && ciProjectId != null) {
    "https://$ciServerHost/api/v4/projects/$ciProjectId/packages/maven/"
} else {
    "https://git.slock.it/api/v4/projects/1387/packages/maven"
}

publishing {
	publications {
		create<MavenPublication>("release") {
			artifact("build/outputs/aar/android-release.aar") {
				extension = "aar"
			}

			groupId = group.toString()
			artifactId = "agent-sdk-android"
			version = project.version.toString()
		}
	}

	repositories {
		maven {
			val ciHost = System.getenv("CI_SERVER_HOST")
			val ciProjectId = System.getenv("CI_PROJECT_ID")

			url = uri(
				if (ciHost != null && ciProjectId != null)
					"https://$ciHost/api/v4/projects/$ciProjectId/packages/maven/"
				else
					"https://git.slock.it/api/v4/projects/1387/packages/maven"
			)

			credentials {
				username = "gitlab-ci-token"
				password = System.getenv("CI_JOB_TOKEN")
			}
		}
	}
}


android {
    namespace = "com.bci.asdk"
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
