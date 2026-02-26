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

import com.android.build.api.instrumentation.AsmClassVisitorFactory
import com.android.build.api.instrumentation.ClassContext
import com.android.build.api.instrumentation.ClassData
import com.android.build.api.instrumentation.InstrumentationParameters
import io.junglicode.paranoid.processor.StringLiteralsClassPatcher
import io.junglicode.paranoid.processor.StringRegistry
import io.junglicode.paranoid.processor.StringRegistryImpl
import io.junglicode.paranoid.processor.model.Deobfuscator
import com.joom.grip.mirrors.getObjectTypeByInternalName
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.commons.Method

abstract class ParanoidClassesTransform :
  AsmClassVisitorFactory<ParanoidClassesTransform.Parameters> {

  interface Parameters : InstrumentationParameters {
    /**
     * The AES-256 key as a list of 32 integers (each holding 1 byte value 0-255).
     * Stored as List<Int> because Gradle's @Input properties don't support ByteArray directly.
     */
    @get:Input
    val aesKeyBytes: ListProperty<Int>

    @get:Input
    val projectName: Property<String>

    @get:Input
    val enabled: Property<Boolean>
  }

  override fun createClassVisitor(
    classContext: ClassContext,
    nextClassVisitor: ClassVisitor
  ): ClassVisitor {
    if (!parameters.get().enabled.get()) {
      return nextClassVisitor
    }

    val aesKey = parameters.get().aesKeyBytes.get().map { it.toByte() }.toByteArray()
    val stringRegistry = StringRegistryImpl(aesKey)
    val projectName = parameters.get().projectName.get()
    val internalName = "io/junglicode/paranoid/Deobfuscator$$projectName"
    val type = getObjectTypeByInternalName(internalName)
    val method = Method(
      "getString",
      Type.getType(String::class.java),
      arrayOf(Type.LONG_TYPE, Type.getType("[[B"), Type.getType("[[I"))
    )
    val deobfuscator = Deobfuscator(type, method)

    return StringLiteralsClassPatcher(
      deobfuscator = deobfuscator,
      stringRegistry = stringRegistry,
      asmApi = Opcodes.ASM9,
      delegate = nextClassVisitor
    )
  }

  override fun isInstrumentable(classData: ClassData): Boolean {
    return parameters.get().enabled.get() &&
      !classData.className.startsWith("io.junglicode.paranoid.Deobfuscator")
  }
}
