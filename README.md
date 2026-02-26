# Paranoid — String Obfuscator for Android

[![Build](https://github.com/JungliBro/paranoid/actions/workflows/build.yml/badge.svg)](https://github.com/JungliBro/paranoid/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> **Actively maintained fork** of [michaelrocks/paranoid](https://github.com/michaelrocks/paranoid) — original project was abandoned in 2019. This fork brings full **AGP 8+ support** and upgrades the string encryption from a simple XOR cipher to **AES-256-CTR** with a scattered key that is unique to every build.

---

## What's New in This Fork

| | Original (abandoned) | This Fork |
|---|---|---|
| Android Gradle Plugin | 7.0.3 ❌ | **8.3.2 ✅** |
| Gradle | 7.3.1 | **8.7** |
| Kotlin | 1.5.32 | **1.9.25** |
| Java | 8 | **17** |
| compileSdk | 31 | **34** |
| Encryption | XOR stream cipher (reversible) | **AES-256-CTR** (cryptographically secure) |
| Key storage | Seed visible in DEX | **Key split into 8 scattered inner classes** |
| Key per build | Same (predictable) | **Fresh `SecureRandom` key every build** |
| Gradle Transform | Deprecated `Transform` API | **`AsmClassVisitorFactory` (AGP 8+ API)** |

---

## How the AES Encryption Works

Every time you build your app, a **new random 256-bit AES key** is generated using `SecureRandom`. This key is **never stored as a single constant** — it is split into 8 fragments and scattered across generated inner classes (`Deobfuscator$K0` … `Deobfuscator$K7`) as unrecognizable `int[]` arrays:

```
classes.dex
├── YourActivity.class
│     LDC "secret"  →  invokestatic Deobfuscator.getString(42L)   ← no string!
│
├── io/michaelrocks/paranoid/Deobfuscator$App.class
│     static byte[][] data = { ... AES encrypted bytes ... }
│
├── io/michaelrocks/paranoid/Deobfuscator$App$K0.class
│     static int[] V = { 0x3F2B8A1C }   ← key fragment 1 of 8
├── io/michaelrocks/paranoid/Deobfuscator$App$K1.class
│     static int[] V = { 0xC4D9112A }   ← key fragment 2 of 8
│   ... (K2 through K7)
```

At runtime, the 8 fragments are assembled in RAM, AES-CTR decryption runs, and the plain string is returned. **The full key never exists in the DEX file** — even if an attacker extracts all 8 fragments, they still need to know the correct assembly order (which is only in the Deobfuscator class).

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
    classpath 'com.github.JungliBro:paranoid:1.0.0'
  }
}
```

### Step 2 — Apply the plugin (AFTER the Android plugin)

**App-level `build.gradle`**:
```groovy
apply plugin: 'com.android.application'
apply plugin: 'io.michaelrocks.paranoid'   // must be AFTER android plugin
```

### Step 3 — Annotate classes you want to protect

```kotlin
import io.michaelrocks.paranoid.Obfuscate

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
    id("io.michaelrocks.paranoid")
}

paranoid {
    isEnabled = true
    includeSubprojects = false
    isCacheable = false
}
```

---

## Before / After Compilation

**Before (your source code):**
```kotlin
@Obfuscate
class Config {
    val apiKey = "sk-live-super-secret"
}
```

**After (compiled DEX — what attacker sees):**
```java
// No string constants visible anywhere in the class
public class Config {
    public String getApiKey() {
        return Deobfuscator$App.getString(281474976710657L); // ← just an ID
    }
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
- AGP 8+ migration (Transform API → AsmClassVisitorFactory)
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
