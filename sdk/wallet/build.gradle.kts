plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.siros.sdk.wallet"
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
    // Internal SDK modules — transitive, so the app gets everything via :sdk:wallet
    api(project(":sdk:transport"))
    api(project(":sdk:auth"))
    api(project(":sdk:keystore"))
    api(project(":sdk:flow"))
    api(project(":sdk:credentials"))

    // Registry provider API — DigitalCredentialRegistry takes the matcher as
    // a plain ByteArray, which is what makes supplying our own supported
    // rather than a workaround.
    implementation(libs.androidx.credentials.registry.provider)
    implementation(libs.androidx.credentials.registry.provider.play)
    // Only for the stock-matcher fallback path.
    implementation(libs.androidx.credentials.registry.mdoc)
    implementation(libs.androidx.credentials.registry.openid)
    implementation(libs.androidx.credentials.registry.sdjwtvc)
    // Registering through this directly, alongside the AndroidX registry
    // provider above, rather than instead of it — see the doc comment on
    // SirosCredentialRegistry.registerLegacyType for why both are needed.
    implementation(libs.play.services.identity.credentials)

    api(project(":sdk:idv"))

    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play)
    implementation(libs.androidx.security.crypto)
    implementation(libs.timber)
    // JWS verification for signed/multisigned DC API JAR requests (Appendix A) -
    // sdk:keystore depends on this too, but only as `implementation`, so it
    // isn't visible here transitively.
    implementation(libs.nimbus.jose.jwt)
    // JSON Schema (2020-12) validation of transaction_data payloads (EC TS12
    // 3.2 step 4). Validates a kotlinx JsonElement; never fetches a $ref itself,
    // every referenced schema is registered by this SDK.
    implementation(libs.json.schema.validator)

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.kotlin.reflect)
    testImplementation(libs.okhttp.mockwebserver)

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
