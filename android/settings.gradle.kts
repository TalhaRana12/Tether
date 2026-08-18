// Android client. Spec Phase 6 builds this; Phase 0 only requires the project to exist.
//
// Dependency resolution is locked to declared repositories only. FAIL_ON_PROJECT_REPOS
// means a subproject cannot quietly add its own repository — the Android equivalent of
// cargo-deny's `sources` check, and the same T16 concern: code nobody audited entering a
// binary that runs on family members' devices.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "tether"
include(":app")
