// tether Android client. Spec Phase 6 implements it; Phase 0 requires only that the
// project exists and lints.
//
// Rules that bind this module, from docs/engineering/kotlin-hard-rules.md:
//   KT-1  validate every frame before MediaCodec — resolution and NAL caps, SPS/PPS
//         bounds. The host chooses every byte fed to a vendor decoder (T25, §6.17).
//   KT-4  Keystore + StrongBox, setUserAuthenticationRequired(true),
//         setInvalidatedByBiometricEnrollment(true) — a coerced new fingerprint
//         DESTROYS the key rather than unlocking it (HR-4.4, T3).
//   KT-6  SystemClock.elapsedRealtime() for every local expiry, never wall clock —
//         it is user-settable on Android with no privilege at all (HR-6.1, T29).
//   KT-9  no Ctrl+Alt+Del control anywhere; it cannot work (HR-14.3).
//   KT-13 never log session content, frames, clipboard, keys, or input events.

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.tether.client"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.tether.client"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            // HR-8.5: no debuggable release builds. Stated here as well as in the
            // manifest because this is the value that actually reaches the APK.
            isDebuggable = false
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            // Suffixed so a debug build can never be mistaken for, or installed over, a
            // release build on the same device.
            applicationIdSuffix = ".debug"
            isDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // Portable, unlike an absolute org.gradle.java.home path. This pins the JDK used to
    // COMPILE, independently of whichever JDK happens to be running Gradle, so the same
    // bytecode comes out on a laptop and on a CI runner. Same reasoning as
    // rust-toolchain.toml pinning rustc (HR-12.5).
    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(17))
        }
    }

    kotlinOptions {
        jvmTarget = "17"
        // KT-16 forbids `!!`. Treating warnings as errors keeps the smaller lapses —
        // unused results, deprecated Keystore calls — from accumulating into noise
        // nobody reads.
        allWarningsAsErrors = true
    }

    lint {
        // Spec Phase 0: "Fail on any advisory." A lint that warns is a lint that gets
        // scrolled past.
        warningsAsErrors = true
        abortOnError = true
        // The security checks that matter most for this app are not optional.
        checkDependencies = true
        // Written to a file so CI can attach it; the authoritative manifest gate is
        // internal/cigates/android_manifest_test.go, which needs no SDK.
        xmlReport = true
        htmlReport = false
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
    }
}

dependencies {
    // Phase 6 adds Compose, CameraX, ML Kit, and the WebRTC SDK. Deliberately empty at
    // Phase 0: an unused dependency is still a dependency, and cargo-deny's reasoning
    // (T16) applies to Maven just as much as to crates.io.
}
