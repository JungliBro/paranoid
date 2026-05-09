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

package io.junglicode.paranoid.processor

import com.joom.grip.Grip
import com.joom.grip.GripFactory
import com.joom.grip.io.DirectoryFileSink
import com.joom.grip.io.IoFactory
import com.joom.grip.mirrors.getObjectTypeByInternalName
import io.junglicode.paranoid.processor.commons.closeQuietly
import io.junglicode.paranoid.processor.logging.getLogger
import io.junglicode.paranoid.processor.model.Deobfuscator
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
  // The app's applicationId (e.g. "com.example.myapp").
  // When provided, the Deobfuscator class is placed inside the app's own package
  // so it is indistinguishable from the app's own code and cannot be found by
  // NP Manager's fixed library-prefix search.
  private val appPackage: String = "",
  private val asmApi: Int = Opcodes.ASM9,
  // Optional: caller may provide a pre-generated AES key (for deterministic builds).
  // If null, a fresh SecureRandom key is generated each run.
  private val aesKey: ByteArray? = null,
) {

  private val logger = getLogger()

  private val grip: Grip = GripFactory.newInstance(asmApi).create((inputs + classpath + bootClasspath).map { it.toPath() })

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
      IoFactory.createFileSource(input.toPath()) to IoFactory.createFileSink(input.toPath(), output.toPath())
    }

    try {
      Patcher(deobfuscator, stringRegistry, analysisResult, grip.classRegistry, asmApi)
        .copyAndPatchClasses(sourcesAndSinks)

      DirectoryFileSink(genPath.toPath()).use { sink ->
        val generator = DeobfuscatorGenerator(deobfuscator, stringRegistry, grip.classRegistry, buildAesKey)

        // 1. Write the main Deobfuscator class
        val deobfuscatorBytes = generator.generateDeobfuscator()
        sink.createFile("${deobfuscator.type.internalName}.class", deobfuscatorBytes)
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
    // Build the internal name of the generated Deobfuscator class.
    //
    // Strategy: embed it inside the *app's own package* so it looks like just
    // another app class. NP Manager searches for fixed library prefixes like
    // "io/junglicode/paranoid/" — placing the class under the app's package
    // breaks that search entirely, and every developer gets a unique path.
    //
    // Name scheme: {app_package_path}/paranoid/{shortHex}
    //   shortHex  = first 4 bytes of AES key as hex  (unique per build, not a secret)
    //
    // Example: com/example/myapp/paranoid/Dfa3b9c1
    val deobfuscatorInternalName: String = if (appPackage.isNotBlank()) {
      val pkgPath = appPackage.replace('.', '/')
      // Use first 4 bytes of the per-build AES key to make the name unique per build.
      val keyHex = buildAesKey.take(4).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
      "$pkgPath/paranoid/D$keyHex"
    } else {
      // Fallback for non-Android projects or missing applicationId
      "io/junglicode/paranoid/Deobfuscator${composeDeobfuscatorNameSuffix()}"
    }

    val deobfuscatorType = getObjectTypeByInternalName(deobfuscatorInternalName)
    // The proxy method signature only takes the id; data and keyParts are static fields.
    val deobfuscationMethod = Method(
      "getString",
      Type.getType(String::class.java),
      arrayOf(Type.LONG_TYPE)
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
