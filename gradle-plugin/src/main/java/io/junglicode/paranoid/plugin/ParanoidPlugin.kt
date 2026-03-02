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

package io.junglicode.paranoid.plugin

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

    // Project-wide AES key for deterministic/cacheable builds
    val aesKey = generateAesKey()

    val androidComponents = project.extensions.getByType(AndroidComponentsExtension::class.java)
    androidComponents.onVariants { variant ->
      if (!extension.isEnabled) return@onVariants

      val projectName = project.path
        .filter { it.isLetterOrDigit() || it == '_' || it == '$' }
        .let { name -> if (name.isEmpty() || name.startsWith('$')) name else "\$$name" }

      val taskProvider = project.tasks.register(
        "paranoid${variant.name.replaceFirstChar { it.uppercase() }}",
        ParanoidTask::class.java
      ) { task ->
        task.projectName.set(projectName)
        task.aesKeyBytes.set(aesKey.map { it.toInt() and 0xFF })
        task.obfuscationSeed.set(extension.obfuscationSeed ?: 0)
        task.bootClasspath.set(android.bootClasspath)
        // Wire the full compile classpath for class hierarchy lookups
        task.classpath.setFrom(variant.compileClasspath)
      }

      variant.artifacts.forScope(com.android.build.api.variant.ScopedArtifacts.Scope.PROJECT)
        .use(taskProvider)
        .toTransform(
          com.android.build.api.artifact.ScopedArtifact.CLASSES,
          ParanoidTask::allJars,
          ParanoidTask::allDirectories,
          ParanoidTask::output
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
    dependencies.add(configurationName, "com.github.JungliBro.paranoid:paranoid-core:$version")
  }
}
