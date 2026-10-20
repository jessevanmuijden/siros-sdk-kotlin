pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    // Maven Central publishing through the Central Portal publisher API.
    // Nmcp takes the publications the root build's `maven-publish`
    // convention creates (see build.gradle.kts) and uploads them as ONE
    // deployment, so a release either lands whole or not at all. It does not
    // create publications itself.
    id("com.gradleup.nmcp.settings") version "1.6.2"
}

nmcpSettings {
    centralPortal {
        // Central Portal user token (not a login), as org-level Actions secrets.
        // Plain values, not providers: the settings plugin's lifecycle action
        // is isolated and cannot serialize a provider.
        username = System.getenv("CENTRAL_USERNAME") ?: ""
        password = System.getenv("CENTRAL_PASSWORD") ?: ""
        // AUTOMATIC: a deployment that passes Central's validation is
        // published without a human in the portal. 0.14.0 went through as
        // USER_MANAGED and was inspected and published by hand first. A
        // published version is immutable: a bad tag cannot be recalled, only
        // superseded.
        publishingType = "AUTOMATIC"
        publicationName = "siros-sdk-kotlin"
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Dev override for PR-built native libraries: -PsirosNativeRepo=<dir> (or in ~/.gradle/gradle.properties) adds a
        // plain Maven directory FIRST, so AARs built by tools/build-native-aars.sh resolve without being published
        // (see docs/NATIVE_DEV.md).
        providers.gradleProperty("sirosNativeRepo").orNull?.let { dir ->
            maven {
                name = "SirosNativeLocal"
                url = uri(file(dir))
            }
        }
        mavenLocal() // local-dev override: must precede GitHubPackages so local builds win
        // siros-wscd-manager AAR, published to GitHub Packages Maven.
        // Credentials come from env (CI: GITHUB_ACTOR/GITHUB_TOKEN) or Gradle
        // properties (local: gpr.user/gpr.key in ~/.gradle/gradle.properties).
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/sirosfoundation/siros-wscd-manager")
            credentials {
                username = providers.gradleProperty("gpr.user").orElse(
                    providers.environmentVariable("GITHUB_ACTOR")
                ).getOrElse("")
                password = providers.gradleProperty("gpr.key").orElse(
                    providers.environmentVariable("GITHUB_TOKEN")
                ).getOrElse("")
            }
        }
        // siros-dc-matcher AAR — the DC API credential matcher and the CBOR
        // encoder for the blob it reads, shipped together so a wallet cannot
        // pair a writer with a reader that predates it. Its own GH Packages
        // Maven for the same per-repo-scoping reason as the entries below.
        maven {
            name = "GitHubPackagesDcMatcher"
            url = uri("https://maven.pkg.github.com/sirosfoundation/siros-dc-matcher")
            credentials {
                username = providers.gradleProperty("gpr.user").orElse(
                    providers.environmentVariable("GITHUB_ACTOR")
                ).getOrElse("")
                password = providers.gradleProperty("gpr.key").orElse(
                    providers.environmentVariable("GITHUB_TOKEN")
                ).getOrElse("")
            }
        }
        // zk-cred-bbs AAR — blind BBS with hardware key binding. Separate
        // entry for the same reason as zk-cred-longfellow below: GH Packages
        // Maven repos are scoped per-repo, not org-wide.
        maven {
            name = "GitHubPackagesZkCredBbs"
            url = uri("https://maven.pkg.github.com/sirosfoundation/zk-cred-bbs")
            credentials {
                username = providers.gradleProperty("gpr.user").orElse(
                    providers.environmentVariable("GITHUB_ACTOR")
                ).getOrElse("")
                password = providers.gradleProperty("gpr.key").orElse(
                    providers.environmentVariable("GITHUB_TOKEN")
                ).getOrElse("")
            }
        }
        // zk-cred-longfellow AAR, published to its own GitHub Packages Maven -
        // each GH Packages Maven repo is scoped per-repo, not shared org-wide,
        // so this is a separate entry from siros-wscd-manager's above even
        // though the credentials are the same.
        maven {
            name = "GitHubPackagesZkCredLongfellow"
            url = uri("https://maven.pkg.github.com/sirosfoundation/zk-cred-longfellow")
            credentials {
                username = providers.gradleProperty("gpr.user").orElse(
                    providers.environmentVariable("GITHUB_ACTOR")
                ).getOrElse("")
                password = providers.gradleProperty("gpr.key").orElse(
                    providers.environmentVariable("GITHUB_TOKEN")
                ).getOrElse("")
            }
        }
        // zk-cred-vega AAR, published to its own GitHub Packages Maven as of
        // v0.0.2 - same per-repo-scoped reasoning as zk-cred-longfellow above.
        // See VegaProofSystem.kt's own doc comment for the crate's current
        // status (expert review still pending - not for real relying-party
        // use yet, but the circuit is published for early testing).
        maven {
            name = "GitHubPackagesZkCredVega"
            url = uri("https://maven.pkg.github.com/sirosfoundation/zk-cred-vega")
            credentials {
                username = providers.gradleProperty("gpr.user").orElse(
                    providers.environmentVariable("GITHUB_ACTOR")
                ).getOrElse("")
                password = providers.gradleProperty("gpr.key").orElse(
                    providers.environmentVariable("GITHUB_TOKEN")
                ).getOrElse("")
            }
        }
    }
}

rootProject.name = "siros-sdk-kotlin"

include(":sdk:transport")
include(":sdk:auth")
include(":sdk:keystore")
include(":sdk:flow")
include(":sdk:credentials")
include(":sdk:wallet")
include(":sdk:idv")
include(":sdk:passkey-provider")
include(":sdk:bom")
include(":sample-app")
