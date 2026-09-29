plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.compose.compiler)
}

android {
    namespace = "org.siros.sdk.sample"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.siros.sdk.sample"
        minSdk = 28
        targetSdk = 36
        versionCode = 23
        versionName = "0.20.3"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // The SDK's matcher is the default: it understands everything the
        // stock one does, plus the formats the stock one refuses. Build with
        // -PstockDcMatcher=true to fall back to AndroidX's, which is worth
        // keeping reachable in case a platform change ever makes a
        // wallet-supplied matcher unwelcome.
        buildConfigField(
            "boolean",
            "STOCK_DC_MATCHER",
            (project.findProperty("stockDcMatcher") == "true").toString(),
        )
    }

    signingConfigs {
        getByName("debug") {
            // A committed, stable keystore instead of AGP's implicit
            // per-machine ~/.android/debug.keystore: CI runners are
            // ephemeral, so without this every CI-built debug APK gets a
            // fresh random signing key, silently invalidating any
            // Digital Asset Links (assetlinks.json) fingerprint entry
            // added for a previous release.
            //
            // The key is public: this repository is, and so is the
            // password. That is the trust boundary, so be clear about what
            // an assetlinks.json entry for its fingerprint means - "some
            // debug build of the sample app", which anyone with the file
            // can produce, never "a build we vouch for". It is only fit for
            // development and test environments, and is never used for a
            // Play Store upload; release builds sign with their own key.
            storeFile = file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            manifestPlaceholders["usesCleartextTraffic"] = "false"
            buildConfigField("String", "DEFAULT_BACKEND_URL", "\"https://wallet.sirosid.dev\"")
            buildConfigField("String", "ISSUER_PROXY_URL", "\"\"")
            buildConfigField("boolean", "R2PS_ENABLED", "false")
            buildConfigField("boolean", "SHOW_PRE_LOGIN_SETTINGS", "true")
            // 0 = unset/disabled - native attestation stays off until a real
            // Play Console/Firebase cloud project number is supplied (can't
            // be hardcoded into the SDK/sample app).
            buildConfigField("long", "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", "0L")
        }
        debug {
            signingConfig = signingConfigs.getByName("debug")
            // Allow connecting to local backend over cleartext for development
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            // Waydroid reaches host-mapped wallet backend via gateway + wallet-proxy
            buildConfigField("String", "DEFAULT_BACKEND_URL", "\"http://127.0.0.1:8080\"")
            // Rewrite Docker-internal issuer URLs to the host-accessible proxy
            buildConfigField("String", "ISSUER_PROXY_URL", "\"http://192.168.240.1:8091\"")
            // Enable WSCD-backed signing via R2PS in debug builds
            // Requires siros-wscd-manager native lib built with r2ps feature
            buildConfigField("boolean", "R2PS_ENABLED", "false")
            buildConfigField("boolean", "SHOW_PRE_LOGIN_SETTINGS", "true")
            buildConfigField("long", "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", "0L")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
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
    implementation(project(":sdk:wallet"))
    implementation(project(":sdk:keystore"))
    implementation(project(":sdk:passkey-provider"))

    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.okhttp)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play)

    // W3C Digital Credentials API - credential provider registration (alpha)
    implementation(libs.androidx.credentials.registry.provider)
    implementation(libs.androidx.credentials.registry.provider.play)
    implementation(libs.androidx.credentials.registry.mdoc)
    implementation(libs.androidx.credentials.registry.openid)
    implementation(libs.androidx.credentials.registry.sdjwtvc)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.extended)
    implementation(libs.compose.ui.tooling.preview)
    debugImplementation(libs.compose.ui.tooling)
    debugImplementation(libs.compose.ui.test.manifest)

    implementation(libs.timber)

    // QR code scanning
    implementation(libs.camerax.core)
    implementation(libs.camerax.camera2)
    implementation(libs.camerax.lifecycle)
    implementation(libs.camerax.view)
    implementation(libs.mlkit.barcode)

    // QR code generation (mdoc: device engagement display)
    implementation(libs.zxing.core)

    // Credential image loading (SVG decoder needed for VCTM svg_templates rendering)
    implementation(libs.coil.compose)
    implementation(libs.coil.svg)

    // CBOR codec for CTAP2 USB HID transport (FIDO2 plugin)
    implementation(libs.upokecenter.cbor)

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.mockwebserver)

    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.compose.ui.test.junit4)
    // Pinned past the BOM/transitive default (3.5.0): that version's
    // input-injection code calls android.hardware.input.InputManager
    // .getInstance() via reflection, which newer platform releases
    // removed - every performTouchInput/performClick call in an
    // instrumented test fails with NoSuchMethodException on such a
    // device without this.
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
