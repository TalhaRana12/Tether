// Root build file. Plugin versions are pinned here so every module resolves the same
// ones — the Gradle equivalent of Cargo.lock, and required for the same reason (HR-12.5:
// two builds of the same commit must be byte-identical).
//
// `apply false` means the root project declares the versions and each module opts in.
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
}
