plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "org.siros.sdk.idv"
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

// The FaceTec AAR that FaceTec10ApiContractTest checks FaceTecApi's reflection against. It is
// deliberately not a compile or runtime dependency: FaceTecApi binds the SDK by reflection so
// the licensed AAR stays out of this module's published artifact and the host app supplies it
// at runtime. This configuration only puts the file where the test can read it.
//
// Without it the test falls back to whatever `10.*` happens to sit in the developer's Gradle
// cache, and skips when there is none - so it passes on a machine that has built a FaceTec app
// and silently skips in CI, which is how the FaceTec 9 -> 10 break (#246) got in.
val facetecAar: Configuration by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
    isTransitive = false
}

val facetecMavenConfigured = providers.gradleProperty("facetecMavenUrl")
    .orElse(providers.environmentVariable("FACETEC_MAVEN_URL"))
    .getOrElse("").isNotBlank()

// Pinned rather than `10.+` so CI and a developer machine check the same API. Published
// versions in sirosfoundation/vendor-maven-packages are 10.1.4, 10.1.17 and 10.1.21; bump this
// deliberately, and the contract test tells you if the reflection has to change with it.
val facetecSdkVersion = providers.gradleProperty("facetecSdkVersion").getOrElse("10.1.21")

dependencies {
    implementation(libs.kotlinx.coroutines.android)

    if (facetecMavenConfigured) {
        facetecAar("com.facetec:facetec-sdk:$facetecSdkVersion@aar")
    }

    testImplementation(libs.junit)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.org.json)
    testImplementation(libs.mockk)
}

// Hands the pinned AAR to FaceTec10ApiContractTest, which reads FACETEC_SDK_AAR in preference
// to its Gradle-cache fallback. Resolution happens here, so a configured-but-unreachable
// repository fails the build instead of degrading to a skipped check.
if (facetecMavenConfigured) {
    val facetecAarPath = facetecAar.elements.map { it.single().asFile.absolutePath }
    tasks.withType<Test>().configureEach {
        inputs.files(facetecAar).withPropertyName("facetecAar")
        doFirst { environment("FACETEC_SDK_AAR", facetecAarPath.get()) }
    }
}
