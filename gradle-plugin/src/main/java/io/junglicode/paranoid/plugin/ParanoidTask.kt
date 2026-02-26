/*
 * Copyright 2024 Jitendra Kumar
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
import org.gradle.api.DefaultTask
import org.gradle.api.file.Directory
import org.gradle.api.file.RegularFile
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CompileClasspath
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import org.objectweb.asm.Opcodes
import java.io.File
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry

abstract class ParanoidTask : DefaultTask() {

  @get:InputFiles
  abstract val allJars: ListProperty<RegularFile>

  @get:InputFiles
  abstract val allDirectories: ListProperty<Directory>

  @get:OutputFile
  abstract val output: RegularFileProperty

  @get:Input
  abstract val aesKeyBytes: ListProperty<Int>

  @get:Input
  abstract val projectName: Property<String>

  @get:Input
  abstract val obfuscationSeed: Property<Int>

  @get:CompileClasspath
  abstract val bootClasspath: ListProperty<File>

  @get:CompileClasspath
  abstract val classpath: ConfigurableFileCollection

  @TaskAction
  fun transform() {
    val outputJar = output.get().asFile
    outputJar.delete()

    val tempDir = File(temporaryDir, "transformed")
    tempDir.deleteRecursively()
    tempDir.mkdirs()

    val inputs = mutableListOf<File>()
    val outputs = mutableListOf<File>()

    allJars.get().forEachIndexed { index, jar ->
       val input = jar.asFile
       val output = File(tempDir, "jar-$index.jar")
       inputs.add(input)
       outputs.add(output)
    }

    allDirectories.get().forEachIndexed { index, dir ->
       val input = dir.asFile
       val output = File(tempDir, "dir-$index")
       output.mkdirs()
       inputs.add(input)
       outputs.add(output)
    }

    val aesKey = aesKeyBytes.get().map { it.toByte() }.toByteArray()
    val projectName = projectName.get()
    val seed = obfuscationSeed.get()

    val processor = ParanoidProcessor(
      obfuscationSeed = seed,
      inputs = inputs,
      outputs = outputs,
      genPath = tempDir, // Generated classes go to tempDir
      classpath = classpath.files.toList(),
      bootClasspath = bootClasspath.get(),
      projectName = projectName,
      asmApi = Opcodes.ASM9,
      aesKey = aesKey
    )

    processor.process()

    // Now merge all outputs (jars and dirs) into the final outputJar
    JarOutputStream(outputJar.outputStream()).use { jarStream ->
      // 1. Merge processed jars
      outputs.filter { it.extension == "jar" }.forEach { jarFile ->
        java.util.zip.ZipFile(jarFile).use { zip ->
           zip.entries().asSequence().forEach { entry ->
             if (!entry.isDirectory) {
               jarStream.putNextEntry(ZipEntry(entry.name))
               zip.getInputStream(entry).copyTo(jarStream)
               jarStream.closeEntry()
             }
           }
        }
      }

      // 2. Merge processed directories (and generated classes)
      outputs.filter { it.isDirectory }.forEach { dir ->
        dir.walkTopDown().filter { it.isFile }.forEach { file ->
           val relativePath = file.relativeTo(dir).path
           jarStream.putNextEntry(ZipEntry(relativePath))
           file.inputStream().copyTo(jarStream)
           jarStream.closeEntry()
        }
      }
      
      // 3. Merge generated classes from genPath (which is tempDir)
      // They are already in tempDir, but we need to find them.
      // Actually, if we use tempDir as genPath, it will contain io/junglicode/paranoid/Deobfuscator...
      // but also the processed directories.
      // We should be careful not to duplicate.
      
      tempDir.walkTopDown().filter { it.isFile && it.name.contains("Deobfuscator") }.forEach { file ->
         val relativePath = file.relativeTo(tempDir).path
         // Avoid duplicates if it was already merged from a processed dir
         try {
           jarStream.putNextEntry(ZipEntry(relativePath))
           file.inputStream().copyTo(jarStream)
           jarStream.closeEntry()
         } catch (e: java.util.zip.ZipException) {
           // Entry already exists, skip
         }
      }
    }
  }
}
