import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "dev.xiaoqiong.vkey"
    compileSdk = 35

    // 正式签名配置：优先读 <repo>/android/keystore.properties（不入库），
    // 其次读环境变量 VKEY_KEYSTORE_*。两者都缺失时 release 无签名（CI 会拒绝发布）。
    val keystoreProps = Properties().apply {
        val f = rootProject.file("keystore.properties")
        if (f.isFile) f.inputStream().use { load(it) }
    }
    fun signingValue(key: String, env: String): String? =
        keystoreProps.getProperty(key) ?: System.getenv(env)

    defaultConfig {
        applicationId = "dev.xiaoqiong.vkey"
        minSdk = 26
        targetSdk = 35
        versionCode = 30100
        versionName = "0.3.1"
    }

    buildFeatures {
        compose = true
        // 更新检查需要读取 BuildConfig.VERSION_CODE / VERSION_NAME
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    signingConfigs {
        create("release") {
            val storePath = signingValue("storeFile", "VKEY_KEYSTORE_FILE")
            val storePassword = signingValue("storePassword", "VKEY_KEYSTORE_PASSWORD")
            val keyAlias = signingValue("keyAlias", "VKEY_KEY_ALIAS")
            val keyPassword = signingValue("keyPassword", "VKEY_KEY_PASSWORD")
            if (storePath != null && storePassword != null && keyAlias != null && keyPassword != null) {
                storeFile = file(storePath)
                this.storePassword = storePassword
                this.keyAlias = keyAlias
                this.keyPassword = keyPassword
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
    }

    // 「关于」页从 assets/LICENSE 读取许可声明：把仓库根的 LICENSE 复制进 assets，
    // 保持单一真源（不要在仓库里维护第二份副本）。
    sourceSets["main"].assets.srcDir(layout.buildDirectory.dir("generated/licenseAssets"))

    // 同步/HTTP 层会调用 android.util.Log：单测里按默认值（no-op）返回，避免抛 "not mocked"
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

// 把仓库根的 LICENSE 复制进 assets（「关于」页读取，保持单一真源）。
val copyLicenseToAssets by tasks.registering(Copy::class) {
    val licenseFile = rootProject.file("../LICENSE")
    onlyIf { licenseFile.isFile }
    from(licenseFile)
    into(layout.buildDirectory.dir("generated/licenseAssets"))
}

tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(copyLicenseToAssets)
}

// 单元测试直接读取仓库内的协议向量，避免复制副本导致漂移。
tasks.withType<org.gradle.api.tasks.testing.Test>().configureEach {
    systemProperty("vkey.vectorsDir", rootProject.file("../shared/vectors").absolutePath)
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    // 扫码：CameraX + ML Kit 离线条码识别（bundled，不依赖 Play services）
    implementation("androidx.camera:camera-core:1.4.0")
    implementation("androidx.camera:camera-camera2:1.4.0")
    implementation("androidx.camera:camera-lifecycle:1.4.0")
    implementation("androidx.camera:camera-view:1.4.0")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    // 生成配对码二维码
    implementation("com.google.zxing:core:3.5.3")

    // 同步层：HTTP 客户端 + Ed25519（BouncyCastle lightweight API）
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // 纯 JVM 单元测试
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
}
