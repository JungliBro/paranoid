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

import io.junglicode.paranoid.processor.ParanoidProcessor
import org.gradle.api.artifacts.transform.InputArtifact
import org.gradle.api.artifacts.transform.TransformAction
import org.gradle.api.artifacts.transform.TransformOutputs
import org.gradle.api.artifacts.transform.TransformParameters
import org.gradle.api.file.FileSystemLocation
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import java.io.File
import java.security.SecureRandom

abstract class ParanoidArtifactTransform : TransformAction<ParanoidArtifactTransform.Parameters> {

  interface Parameters : TransformParameters {
    @get:Input
    val obfuscationSeed: Property<Int>

    @get:Input
    val projectName: Property<String>

    @get:Input
    val bootClasspath: ListProperty<String>

    @get:Input
    val isEnabled: Property<Boolean>

    @get:Input
    val isCacheable: Property<Boolean>
  }

  @get:InputArtifact
  @get:PathSensitive(PathSensitivity.NONE)
  abstract val inputArtifact: Provider<FileSystemLocation>

  override fun transform(outputs: TransformOutputs) {
    val input = inputArtifact.get().asFile
    val params = parameters

    if (!params.isEnabled.get()) {
      // If paranoid is disabled, pass through unchanged
      if (input.isDirectory) {
        input.copyRecursively(outputs.dir("passthrough"), overwrite = true)
      } else {
        outputs.file(input.name).also { out ->
          input.copyTo(out, overwrite = true)
        }
      }
      return
    }

    val obfuscationSeed = resolveObfuscationSeed(input, params)
    val bootClasspath = params.bootClasspath.get().map { File(it) }
    val projectName = params.projectName.get()

    val inputFile = input
    val outputFile: File
    val genDir: File

    if (inputFile.isDirectory) {
      outputFile = outputs.dir("classes")
      genDir = outputs.dir("gen-paranoid")
    } else {
      outputFile = outputs.file(inputFile.name)
      genDir = outputs.dir("gen-paranoid")
    }

    val processor = ParanoidProcessor(
      obfuscationSeed = obfuscationSeed,
      inputs = listOf(inputFile),
      outputs = listOf(outputFile),
      genPath = genDir,
      classpath = emptyList(),
      bootClasspath = bootClasspath,
      projectName = projectName
    )

    processor.process()
  }

  private fun resolveObfuscationSeed(input: File, params: Parameters): Int {
    val seed = params.obfuscationSeed.orNull
    return when {
      seed != null -> seed
      !params.isCacheable.get() -> SecureRandom().nextInt()
      else -> ObfuscationSeedCalculator.calculate(listOf(input))
    }
  }
}
