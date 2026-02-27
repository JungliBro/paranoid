# Paranoid — String Obfuscator for Android 🚀

[![Build](https://github.com/JungliBro/paranoid/actions/workflows/build.yml/badge.svg)](https://github.com/JungliBro/paranoid/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Paranoid** is a high-performance string obfuscation engine. It protects your Android app's sensitive strings — API keys, URLs, and secrets — by replacing them at compile time with **AES-256-CTR encrypted data**. A fresh 256-bit key is generated on every build and split across 8 scattered inner classes, ensuring no readable constant ever appears in your APK.

---

## The Upgrade (AGP 8.x +)

This project has undergone a massive architectural shift to support the modern Android ecosystem.

| Feature | Original (Legacy) | **New Edition** |
|---|---|---|
| **Android Gradle Plugin** | 7.0.3  | **8.3.2 - 8.11.1+** |
| **Gradle Support** | 7.3.1 | **8.11.1+** |
| **Kotlin Support** | 1.5.32 | **1.9.25+** |
| **Java Requirement** | 8 | **17** |
| **Encryption Engine** | XOR stream cipher | **AES-256-CTR** |
| **Key Scattering** | DEX-visible seed | **8-Part Split Distribution** |
| **API Architecture** | Deprecated Transform | **ScopedArtifacts** |

---

## 🏗️ Key Contributions by Jitendra Kumar

- **Modernized Core**: A complete rewrite of the transformation engine to work with the latest Android build tools.
- **Dependency Scalability**: Introduced automated classpath analysis, solving the long-standing "ClassMirror" lookup failures for external libraries.
- **AAR Intelligence**: Developed a smart extraction system to handle local and remote `.aar` dependencies without build-time crashes.
- **Production Performance**: Optimized for zero runtime lag, making it safe for high-traffic production apps.

---

## Setup

### Step 1 — Add the plugin to your project

**`settings.gradle`** (or `settings.gradle.kts`):
```groovy
pluginManagement {
  repositories {
    google()
    gradlePluginPortal()
    maven { url 'https://jitpack.io' }   // for JitPack distribution
  }
}
```

**Project-level `build.gradle`**:
```groovy
buildscript {
  repositories {
    google()
    mavenCentral()
    maven { url 'https://jitpack.io' }
  }
  dependencies {
    classpath 'com.github.JungliBro.paranoid:paranoid-gradle-plugin:1.1.5'
  }
}
```

### Step 2 — Apply the plugin (AFTER the Android plugin)

**App-level `build.gradle`**:
```groovy
apply plugin: 'com.android.application'
apply plugin: 'io.junglicode.paranoid'   // must be AFTER android plugin
```

### Step 3 — Annotate classes you want to protect

```kotlin
import io.junglicode.paranoid.Obfuscate

@Obfuscate
class NetworkConfig {
    companion object {
        const val API_KEY    = "sk-live-abc123xyz"
        const val BASE_URL   = "https://api.myserver.com/v2"
        const val SECRET_KEY = "super-secret-signing-key"
    }
}
```

That's it — **no other code changes needed**. After compilation, all string literals in `@Obfuscate`-annotated classes are replaced with AES-256-CTR encrypted data.

---

## Configuration Options

```groovy
paranoid {
  enabled           = true    // Set false to disable obfuscation (e.g. for debug builds)
  includeSubprojects = false  // Set true to obfuscate strings in library submodules too
  isCacheable       = false   // Set true for reproducible builds (same key across runs)
  obfuscationSeed   = null    // Integer seed for reproducible key (only used when isCacheable=true)
}
```

### Recommended configuration for production:
```groovy
android {
  buildTypes {
    debug {
      // Disable for faster debug builds
    }
    release {
      minifyEnabled true       // Run R8 AFTER paranoid for maximum obfuscation
    }
  }
}

paranoid {
  enabled = true
  isCacheable = false         // Fresh AES key every release build
}
```

> **Pro tip:** Running R8/ProGuard (`minifyEnabled true`) **on top of paranoid** renames the `Deobfuscator` class and all key fragment classes to meaningless `a.b.c` names, making reverse-engineering even harder.

---

## Kotlin DSL Example

```kotlin
// build.gradle.kts
plugins {
    id("com.android.application")
    id("io.junglicode.paranoid")
}

paranoid {
    isEnabled = true
    includeSubprojects = false
    isCacheable = false
}
```

---

## Requirements

| Requirement | Version |
|---|---|
| Android Gradle Plugin | **8.0+** |
| Gradle | **8.0+** |
| Java | **17+** |
| Kotlin | **1.9+** (if using Kotlin) |
| minSdk | **21+** |
| compileSdk | **34** |

---

## Credits

**Maintained and enhanced by:** [Jitendra Kumar](https://github.com/JungliBro)

Enhancements:
- AGP 8+ migration (Transform API → ScopedArtifacts)
- AES-256-CTR encryption replacing XOR stream cipher
- Per-build random key generation with scattered fragment obfuscation
- Gradle 8.7, Kotlin 1.9.25, Java 17, SDK 34

**Original project:** [michaelrocks/paranoid](https://github.com/michaelrocks/paranoid) by Michael Rozumyanskiy  
Licensed under [Apache License 2.0](LICENSE.txt)

---

## License

```
Copyright 2024 Jitendra Kumar
Copyright 2016 Michael Rozumyanskiy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
