plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.siros.sdk.flow"
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
    // `api`, not `implementation`: OID4VCIFlowParams exposes AuthorizationDetail
    // (from :sdk:credentials, re-exported by :sdk:transport) in its public API,
    // so a consumer of the flow artifact has to be able to resolve that type.
    api(project(":sdk:transport"))
    implementation(project(":sdk:keystore"))
    implementation(project(":sdk:auth"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.timber)

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.turbine)
}
