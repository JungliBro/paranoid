/*
 * Copyright 2024 Jitendra Kumar
 * Copyright 2016-2021 Michael Rozumyanskiy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.michaelrocks.paranoid.plugin

import com.android.build.api.instrumentation.FramesComputationMode
import com.android.build.api.instrumentation.InstrumentationScope
import com.android.build.api.variant.AndroidComponentsExtension
import com.android.build.gradle.BaseExtension
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.UnknownDomainObjectException
import org.gradle.api.plugins.JavaPlugin
import java.security.SecureRandom

class ParanoidPlugin : Plugin<Project> {
  private lateinit var extension: ParanoidExtension

  override fun apply(project: Project) {
    extension = project.extensions.create("paranoid", ParanoidExtension::class.java)

    val android = try {
      project.extensions.getByName("android") as BaseExtension
    } catch (e: UnknownDomainObjectException) {
      throw GradleException("Paranoid plugin must be applied *AFTER* Android plugin", e)
    }

    // Register paranoid-core runtime dependency
    project.addCoreDependency(getDefaultConfiguration())

    // Generate one AES-256 key per project per build
    // Using SecureRandom — 32 bytes = 256-bit key
    // The key changes every build unless isCacheable=true + obfuscationSeed is set
    val aesKey = generateAesKey()

    val androidComponents = project.extensions.getByType(AndroidComponentsExtension::class.java)
    androidComponents.onVariants { variant ->
      val scope = if (extension.includeSubprojects) {
        InstrumentationScope.ALL
      } else {
        InstrumentationScope.PROJECT
      }

      val projectName = project.path
        .filter { it.isLetterOrDigit() || it == '_' || it == '$' }
        .let { name -> if (name.isEmpty() || name.startsWith('$')) name else "\$$name" }

      variant.instrumentation.transformClassesWith(
        ParanoidClassesTransform::class.java,
        scope
      ) { params ->
        // Pass AES key as List<Int> (Gradle parameters must be serializable)
        params.aesKeyBytes.set(aesKey.map { it.toInt() and 0xFF })
        params.projectName.set(projectName)
        params.isEnabled.set(extension.isEnabled)
      }

      variant.instrumentation.setAsmFramesComputationMode(
        FramesComputationMode.COMPUTE_FRAMES_FOR_INSTRUMENTED_METHODS
      )
    }
  }

  private fun generateAesKey(): ByteArray {
    // If user set a manual obfuscation seed, derive a deterministic key from it
    // so cacheable builds are reproducible. Otherwise use SecureRandom.
    val manualSeed = extension.obfuscationSeed
    return if (manualSeed != null && extension.isCacheable) {
      // Deterministic key: expand the seed using SHA-256
      val seedBytes = ByteArray(4) {
        (manualSeed ushr (24 - it * 8)).toByte()
      }
      java.security.MessageDigest.getInstance("SHA-256").digest(seedBytes)
    } else {
      ByteArray(32).also { SecureRandom().nextBytes(it) }
    }
  }

  private fun getDefaultConfiguration(): String {
    return JavaPlugin.IMPLEMENTATION_CONFIGURATION_NAME
  }

  private fun Project.addCoreDependency(configurationName: String) {
    val version = Build.VERSION
    dependencies.add(configurationName, "io.michaelrocks:paranoid-core:$version")
  }
}
