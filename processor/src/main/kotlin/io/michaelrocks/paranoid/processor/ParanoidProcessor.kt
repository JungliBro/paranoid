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

package io.michaelrocks.paranoid.processor

import com.joom.grip.Grip
import com.joom.grip.GripFactory
import com.joom.grip.io.DirectoryFileSink
import com.joom.grip.io.IoFactory
import com.joom.grip.mirrors.getObjectTypeByInternalName
import io.michaelrocks.paranoid.processor.commons.closeQuietly
import io.michaelrocks.paranoid.processor.logging.getLogger
import io.michaelrocks.paranoid.processor.model.Deobfuscator
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.commons.Method
import java.io.File
import java.security.SecureRandom

class ParanoidProcessor(
  private val obfuscationSeed: Int,
  private val inputs: List<File>,
  private val outputs: List<File>,
  private val genPath: File,
  private val classpath: Collection<File>,
  private val bootClasspath: Collection<File>,
  private val projectName: String,
  private val asmApi: Int = Opcodes.ASM9,
  // Optional: caller may provide a pre-generated AES key (for deterministic builds).
  // If null, a fresh SecureRandom key is generated each run.
  private val aesKey: ByteArray? = null,
) {

  private val logger = getLogger()

  private val grip: Grip = GripFactory.newInstance(asmApi).create(inputs + classpath + bootClasspath)

  /** AES-256 key for this build (32 bytes). Generated once and reused throughout. */
  private val buildAesKey: ByteArray = aesKey ?: generateAesKey()

  private val stringRegistry = StringRegistryImpl(buildAesKey)

  fun process() {
    dumpConfiguration()

    require(inputs.size == outputs.size) {
      "Input collection $inputs and output collection $outputs have different sizes"
    }

    val analysisResult = Analyzer(grip).analyze(inputs)
    analysisResult.dump()

    val deobfuscator = createDeobfuscator()
    logger.info("Prepare to generate {}", deobfuscator)

    val sourcesAndSinks = inputs.zip(outputs) { input, output ->
      IoFactory.createFileSource(input) to IoFactory.createFileSink(input, output)
    }

    try {
      Patcher(deobfuscator, stringRegistry, analysisResult, grip.classRegistry, asmApi)
        .copyAndPatchClasses(sourcesAndSinks)

      DirectoryFileSink(genPath).use { sink ->
        val generator = DeobfuscatorGenerator(deobfuscator, stringRegistry, grip.classRegistry, buildAesKey)

        // 1. Write the main Deobfuscator class
        val deobfuscatorBytes = generator.generateDeobfuscator()
        sink.createFile("${deobfuscator.type.internalName}.class", deobfuscatorBytes)

        // 2. Write scattered AES key fragment classes (K0..K7)
        val fragments = generator.splitKeyIntoFragments()
        fragments.forEachIndexed { index, words ->
          val fragBytes = generator.generateKeyFragmentClass(index, words)
          val fragName = "${deobfuscator.type.internalName}\$K$index.class"
          sink.createFile(fragName, fragBytes)
        }
      }
    } finally {
      sourcesAndSinks.forEach { (source, sink) ->
        source.closeQuietly()
        sink.closeQuietly()
      }
    }
  }

  private fun generateAesKey(): ByteArray {
    val key = ByteArray(32)
    SecureRandom().nextBytes(key)
    return key
  }

  private fun dumpConfiguration() {
    logger.info("Starting ParanoidProcessor (AES-256-CTR mode):")
    logger.info("  inputs        = {}", inputs)
    logger.info("  outputs       = {}", outputs)
    logger.info("  genPath       = {}", genPath)
    logger.info("  classpath     = {}", classpath)
    logger.info("  bootClasspath = {}", bootClasspath)
    logger.info("  projectName   = {}", projectName)
  }

  private fun AnalysisResult.dump() {
    if (configurationsByType.isEmpty()) {
      logger.info("No classes to obfuscate")
    } else {
      logger.info("Classes to obfuscate:")
      configurationsByType.forEach {
        val (type, configuration) = it
        logger.info("  {}:", type.internalName)
        configuration.constantStringsByFieldName.forEach {
          val (field, string) = it
          logger.info("    {} = \"{}\"", field, string)
        }
      }
    }
  }

  private fun createDeobfuscator(): Deobfuscator {
    val deobfuscatorInternalName = "io/michaelrocks/paranoid/Deobfuscator${composeDeobfuscatorNameSuffix()}"
    val deobfuscatorType = getObjectTypeByInternalName(deobfuscatorInternalName)
    // Updated signature: (J [[B [[I) Ljava/lang/String;
    val deobfuscationMethod = Method(
      "getString",
      Type.getType(String::class.java),
      arrayOf(Type.LONG_TYPE, Type.getType("[[B"), Type.getType("[[I"))
    )
    return Deobfuscator(deobfuscatorType, deobfuscationMethod)
  }

  private fun composeDeobfuscatorNameSuffix(): String {
    val normalizedProjectName = projectName.filter { it.isLetterOrDigit() || it == '_' || it == '$' }
    return if (normalizedProjectName.isEmpty() || normalizedProjectName.startsWith('$')) {
      normalizedProjectName
    } else {
      "\$$normalizedProjectName"
    }
  }
}
