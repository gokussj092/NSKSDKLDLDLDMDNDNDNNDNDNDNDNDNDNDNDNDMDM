plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "com.ghostdeveloper.spdecode.admin"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.ghostdeveloper.spdecode.admin"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        externalNativeBuild { cmake { arguments += "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON" } }
    }
    ndkVersion = "27.2.12479018"
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
    buildFeatures { compose = true; buildConfig = true }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    signingConfigs {
        val store=providers.environmentVariable("SPDECODE_RELEASE_STORE_FILE").orNull
        if(!store.isNullOrBlank())create("production") {
            storeFile=file(store)
            storePassword=providers.environmentVariable("SPDECODE_RELEASE_STORE_PASSWORD").orNull
            keyAlias=providers.environmentVariable("SPDECODE_RELEASE_KEY_ALIAS").orNull
            keyPassword=providers.environmentVariable("SPDECODE_RELEASE_KEY_PASSWORD").orNull
            enableV1Signing=true; enableV2Signing=true; enableV3Signing=true
        }
    }
    buildTypes {
        debug { applicationIdSuffix = ".dev"; versionNameSuffix = "-dev" }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig=signingConfigs.findByName("production")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"),"proguard-rules.pro")
        }
    }
}
tasks.configureEach {
    if(name == "preReleaseBuild")doFirst {
        require(listOf("SPDECODE_RELEASE_STORE_FILE","SPDECODE_RELEASE_STORE_PASSWORD","SPDECODE_RELEASE_KEY_ALIAS","SPDECODE_RELEASE_KEY_PASSWORD").all { !System.getenv(it).isNullOrBlank() }) { "Permanent release signing configuration is required" }
    }
}
dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.04.01"))
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation(platform("androidx.compose:compose-bom:2025.04.01"))
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
