import java.util.zip.ZipFile

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.siros.sdk.credentials"
    compileSdk = 36

    defaultConfig {
        minSdk = 28
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }

    // The matcher's zkp_req planner vectors (spec/zkp-req-vectors/zkp_req)
    // are read by the instrumented planner test as assets of the test APK.
    sourceSets.getByName("androidTest").assets.srcDir("../../spec")
}

// The native libraries that carry the nymauth entry points (docs/NATIVE_DEV.md). Until a release of each is published
// to GitHub Packages these coordinates resolve only from a local build (-PsirosNativeRepo=<dir>).
val zkCredVegaVersion: String = providers.gradleProperty("zkCredVegaVersion").getOrElse("0.0.7")
val zkCredLongfellowVersion: String = providers.gradleProperty("zkCredLongfellowVersion").getOrElse("0.1.2")

// The matcher at rulebook v0.4 (`zkp_req`): siros-dc-matcher v0.11.0 (merge 09ac62fb). Its Kotlin bindings (vendored below
// uniffi/) and the vectors in spec/zkp-req-vectors are the ones of that tag.
val sirosDcMatcherVersion: String = providers.gradleProperty("sirosDcMatcherVersion").getOrElse("0.11.0")

/**
 * Fails the build up front, with the coordinates and the way out, instead of a bare resolution error deep in a compile
 * task (or, worse, quietly using an AAR that has no nymauth entry points: ~/.m2 can hold an older build of the same
 * version, and mavenLocal comes before GitHub Packages). Each AAR must resolve and its arm64 library must export the
 * nymauth functions the vendored bindings call.
 */
val checkNativeLibraries = tasks.register("checkNativeLibraries") {
    group = "verification"
    description = "Checks that zk-cred-vega and zk-cred-longfellow resolve and carry the nymauth entry points."
    val nativeLibs = listOf(
        Triple("zk-cred-vega", zkCredVegaVersion, "libzk_cred_vega.so" to "nymauth_vega_load_keys"),
        Triple("zk-cred-longfellow", zkCredLongfellowVersion, "libzk_cred_longfellow.so" to "nymauth_initialize_prover"),
    )
    doLast {
        for ((artifact, version, lib) in nativeLibs) {
            val coordinates = "org.siros:$artifact:$version"
            val files = try {
                configurations.detachedConfiguration(dependencies.create("$coordinates@aar")).apply { isTransitive = false }.resolve()
            } catch (e: Exception) {
                throw GradleException(
                    "The native library $coordinates cannot be resolved.\n" +
                        "It carries the nymauth circuit_zk prover and is not published yet (GitHub Packages: " +
                        "https://maven.pkg.github.com/sirosfoundation/$artifact). Build it from its pull request and point Gradle at it:\n" +
                        "  tools/build-native-aars.sh --vega <zk-cred-vega checkout> --longfellow <zk-cred-longfellow checkout>\n" +
                        "  ./gradlew -PsirosNativeRepo=<repo>/build/native-repo ...\n" +
                        "See docs/NATIVE_DEV.md. (-PzkCredVegaVersion / -PzkCredLongfellowVersion select other versions.)\n" +
                        "Gradle said: ${e.message?.lineSequence()?.firstOrNull().orEmpty()}",
                    // No cause: Gradle would print the resolution error instead of this message.
                )
            }
            val aar = files.single()
            val has = ZipFile(aar).use { zip ->
                val entry = zip.getEntry("jni/arm64-v8a/${lib.first}")
                entry != null && zip.getInputStream(entry).use { it.readBytes() }.let { bytes ->
                    String(bytes, Charsets.ISO_8859_1).contains(lib.second)
                }
            }
            if (!has) {
                throw GradleException(
                    "$coordinates resolved to $aar but its ${lib.first} has no `${lib.second}`: it is an older build of the same version " +
                        "(an old copy in ~/.m2, say). Use the build from the pinned pull request: put -PsirosNativeRepo=<dir> first " +
                        "(docs/NATIVE_DEV.md), or remove the stale artifact from ~/.m2/repository/org/siros/$artifact/$version.",
                )
            }
        }
    }
}
tasks.matching { it.name == "preBuild" }.configureEach { dependsOn(checkNativeLibraries) }

dependencies {
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.timber)
    // Rasterizes display-logo SVGs to PNG (no script engine, no network);
    // see org.siros.sdk.credentials.logo.LogoSanitizer.
    implementation(libs.androidsvg)
    // Reads JPEG/WebP EXIF orientation so re-encoding (which drops metadata) keeps the logo upright.
    implementation(libs.exifinterface)
    // Real HTTP client for ZkCircuitClient (mirrors sdk/auth's BackendApiClient usage).
    implementation(libs.okhttp)
    // Real CBOR codec for ISO 18013-5 mdoc parsing (claim extraction/display).
    // `api` (not `implementation`) since sdk/keystore depends on this module
    // and re-exposes CBORObject-typed values from the mdoc parsing model.
    api(libs.upokecenter.cbor)

    // zk-cred-longfellow UniFFI bindings (AAR from local maven or CI
    // release artifact). The AAR is built by `make aar` in that crate.
    // For local development, publish to mavenLocal:
    //   cd zk-cred-longfellow && make aar && make publish-local
    // The DC API matcher: the CBOR encoder for the blob a wallet registers,
    // matcher.wasm itself as an asset, and the shared DCQL engine. One
    // dependency at one version, so the blob's writer and its reader cannot
    // drift apart.
    //
    // `api`, because :sdk:wallet registers the blob and ships the asset, and
    // consumers of the SDK see the matcher's types through CredentialMatcher.
    api("org.siros:siros-dc-matcher:$sirosDcMatcherVersion")

    // The nymauth entry points (the circuit_zk prover) need the libraries that carry them; the vendored UniFFI
    // bindings are generated from exactly these builds and check their API checksums at load, so the two move
    // together. Override for a local build with -PzkCredLongfellowVersion / -PzkCredVegaVersion (docs/NATIVE_DEV.md).
    implementation("org.siros:zk-cred-longfellow:$zkCredLongfellowVersion")

    // zk-cred-vega UniFFI bindings - real GitHub Packages Maven artifact
    // (resolved via GitHubPackagesZkCredVega in settings.gradle.kts), built
    // against sirosfoundation/vega-prover's fork (a 2-line #[serde(skip)]
    // fix shrinking the FFI prep-state from ~356MB to ~100MB so it fits
    // Android's heap ceiling). v0.0.3 carries a real, independently-flagged
    // privacy fix (undisclosed-claim digest concealment) - see
    // VegaProofSystem.kt's own doc comment for the crate's current status.
    // v0.0.4 bumps vega-prover to sirosfoundation/vega-prover@2a7dcb3, a
    // real measured ~35-40% prove() speedup on x86_64 (chunk-overhead fix
    // in bind_and_prepare_poly_ABC_inner) - not yet confirmed on-device.
    implementation("org.siros:zk-cred-vega:$zkCredVegaVersion")

    // zk-cred-bbs UniFFI bindings - blind BBS with Schnorr key binding.
    // Same shape as above: AAR from GitHub Packages (or mavenLocal via
    // `cd zk-cred-bbs && make publish-local`), Kotlin bindings vendored
    // under src/main/kotlin/uniffi/zk_cred_bbs/.
    implementation("org.siros:zk-cred-bbs:0.0.6")

    // JNA is required by UniFFI-generated Kotlin bindings.
    //
    // `api`, not `implementation`: the vendored bindings are compiled into
    // this module and their public API mentions JNA types — SirosBlobBuilder
    // has a `constructor(pointer: Pointer)`. A consumer touching that surface
    // needs JNA on its own compile classpath, and the failure would be an
    // unresolved reference inside a generated file, a long way from the cause.
    api("net.java.dev.jna:jna:5.14.0@aar")
    // @RequiresApi, used by the Android-aware cleaner in the generated
    // bindings: it guards android.system.SystemCleaner behind an SDK_INT
    // check that lint can read.
    implementation("androidx.annotation:annotation:1.9.1")

    // Instrumented tests: the zk-cred-bbs native library ships as .so files
    // inside its AAR, so anything exercising the UniFFI surface has to run
    // on a device or emulator - a JVM unit test cannot load them.
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation(libs.kotlinx.coroutines.test)

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.okhttp.tls)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
}
