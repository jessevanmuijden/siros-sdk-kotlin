plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.siros.sdk.keystore"
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
}

dependencies {
    api(project(":sdk:credentials"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.serialization.cbor)
    implementation(libs.kotlinx.coroutines.core)
    // Real CBOR codec for ISO 18013-5 mdoc (IssuerSigned/DeviceResponse parsing,
    // COSE_Sign1 construction) - replaces hand-rolled byte-packing.
    implementation(libs.upokecenter.cbor)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.play.integrity)
    implementation(libs.timber)
    // OkHttpR2psTransport, the default R2psTransportProvider.
    implementation(libs.okhttp)

    // siros-wscd-manager UniFFI bindings (AAR from local maven or CI artifact).
    // The AAR is built by `make aar` in the siros-wscd-manager crate.
    // For local development, publish to mavenLocal:
    //   cd siros-wscd-manager && make aar && make publish-local
    implementation("org.siros:siros-wscd-manager:0.12.0")
    // JNA is required by UniFFI-generated Kotlin bindings.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // Circuits fetched from go-zk-circuits (see ZkCircuitClient, sdk/credentials)
    // are zstd-compressed; zk-cred-longfellow's initializeProver expects
    // already-decompressed bytes (confirmed against wallet-frontend's
    // feat/longfellow-zk reference implementation) - decompression is the
    // caller's responsibility, not the native crate's.
    //
    // The `@aar` classifier is required on Android: the plain jar artifact
    // only bundles desktop/server-glibc native libraries (linux/aarch64,
    // freebsd, aix, ...), never real Android/Bionic .so files, and silently
    // resolves at runtime to the wrong one ("Unsupported OS/arch... cannot
    // find /linux/aarch64/libzstd-jni-....so", a genuine dlopen failure on
    // a real device, not just a missing-file warning) - confirmed via a
    // real androidTest run on a Pixel. zstd-jni's own README documents this
    // separate `zstd-jni.aar` artifact for Android 5.0+.
    implementation("com.github.luben:zstd-jni:1.5.6-6@aar")

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)

    // Real-device instrumented tests: the native zk_cred_longfellow/
    // siros_wscd_manager UniFFI libraries only load on an actual Android
    // ABI (arm64-v8a/x86_64 inside the AAR), never in a plain JVM unit
    // test - see LongfellowZkVectorTest (androidTest), which needs these.
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
