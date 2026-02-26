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

import com.joom.grip.ClassRegistry
import com.joom.grip.mirrors.toAsmType
import io.junglicode.paranoid.processor.model.Deobfuscator
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Opcodes.ACC_FINAL
import org.objectweb.asm.Opcodes.ACC_PRIVATE
import org.objectweb.asm.Opcodes.ACC_PUBLIC
import org.objectweb.asm.Opcodes.ACC_STATIC
import org.objectweb.asm.Opcodes.ACC_SUPER
import org.objectweb.asm.Type
import org.objectweb.asm.commons.Method

/**
 * Generates the Deobfuscator class bytecode via ASM.
 *
 * Architecture (AES era):
 *  - `data`      : byte[][] — the AES-CTR encrypted string table, chunked
 *  - `keyParts`  : int[][] — the 8 scattered fragments whose concatenation is the 32-byte AES key
 *  - `getString(long id, byte[][] data, int[][] keyParts)` calls DeobfuscatorHelper
 *
 * The key is split into KEY_FRAGMENT_COUNT int[] inner classes (e.g. K0..K7),
 * each holding (32 / KEY_FRAGMENT_COUNT / 4) ints.
 * At static init time the keyParts array is assembled from those inner classes
 * so no single class ever has the full key — an attacker must inspect all fragments
 * and know the reconstruction order.
 */
class DeobfuscatorGenerator(
  private val deobfuscator: Deobfuscator,
  private val stringRegistry: StringRegistry,
  private val classRegistry: ClassRegistry,
  private val aesKey: ByteArray,
) {

  fun generateDeobfuscator(): ByteArray {
    val writer = StandaloneClassWriter(ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES, classRegistry)
    writer.visit(
      Opcodes.V1_8,
      ACC_PUBLIC or ACC_SUPER,
      deobfuscator.type.internalName,
      null,
      OBJECT_TYPE.internalName,
      null
    )

    writer.generateDataField()
    writer.generateKeyPartsField()
    writer.generateStaticInitializer()
    writer.generateDefaultConstructor()
    writer.generateGetStringMethod()

    writer.visitEnd()
    return writer.toByteArray()
  }

  /**
   * Generates a standalone inner-class bytecode whose sole purpose is to hold
   * one fragment of the AES key as an int[].
   * fragmentIndex: 0-based index (K0 .. K7)
   * words: the int values for this fragment
   */
  fun generateKeyFragmentClass(fragmentIndex: Int, words: IntArray): ByteArray {
    val innerName = "${deobfuscator.type.internalName}\$K$fragmentIndex"
    val writer = ClassWriter(ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES)
    writer.visit(Opcodes.V1_8, ACC_PUBLIC or ACC_SUPER, innerName, null, "java/lang/Object", null)

    // public static final int[] V = { w0, w1, ... };
    writer.visitField(ACC_PUBLIC or ACC_STATIC or ACC_FINAL, "V", "[I", null, null).visitEnd()

    val clinit = writer.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null)
    clinit.visitCode()
    // push array size
    clinit.visitIntInsn(Opcodes.SIPUSH, words.size)
    clinit.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_INT)
    words.forEachIndexed { i, word ->
      clinit.visitInsn(Opcodes.DUP)
      clinit.visitIntInsn(Opcodes.SIPUSH, i)
      clinit.visitLdcInsn(word)
      clinit.visitInsn(Opcodes.IASTORE)
    }
    clinit.visitFieldInsn(Opcodes.PUTSTATIC, innerName, "V", "[I")
    clinit.visitInsn(Opcodes.RETURN)
    clinit.visitMaxs(0, 0)
    clinit.visitEnd()

    writer.visitEnd()
    return writer.toByteArray()
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Field generation for the main Deobfuscator class
  // ──────────────────────────────────────────────────────────────────────────

  private fun ClassVisitor.generateDataField() {
    visitField(ACC_PRIVATE or ACC_STATIC or ACC_FINAL, DATA_FIELD_NAME, DATA_FIELD_TYPE.descriptor, null, null).visitEnd()
  }

  private fun ClassVisitor.generateKeyPartsField() {
    visitField(ACC_PRIVATE or ACC_STATIC or ACC_FINAL, KEY_PARTS_FIELD_NAME, KEY_PARTS_FIELD_TYPE.descriptor, null, null).visitEnd()
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Static initializer — fills data[][] with encrypted bytes and
  //                       keyParts[][] from K0..K(n-1) inner classes
  // ──────────────────────────────────────────────────────────────────────────

  private fun ClassVisitor.generateStaticInitializer() {
    newMethod(Opcodes.ACC_STATIC, METHOD_STATIC_INITIALIZER) {
      val chunkCount = stringRegistry.getChunkCount()
      val deobType = deobfuscator.type.toAsmType()

      // data = new byte[chunkCount][]
      push(chunkCount)
      newArray(BYTE_ARRAY_TYPE)
      putStatic(deobType, DATA_FIELD_NAME, DATA_FIELD_TYPE)

      // Fill each chunk
      for (i in 0 until chunkCount) {
        val chunkBytes = stringRegistry.getChunkBytes(i)
        getStatic(deobType, DATA_FIELD_NAME, DATA_FIELD_TYPE)
        dup()
        push(i)
        push(chunkBytes.size)
        newArray(Type.BYTE_TYPE)
        // fill byte array inline
        chunkBytes.forEachIndexed { byteIdx, byte ->
          dup()
          push(byteIdx)
          push(byte.toInt())
          arrayStore(Type.BYTE_TYPE)
        }
        arrayStore(BYTE_ARRAY_TYPE)
      }
      pop()

      // keyParts = new int[KEY_FRAGMENT_COUNT][]
      push(KEY_FRAGMENT_COUNT)
      newArray(INT_ARRAY_TYPE)
      putStatic(deobType, KEY_PARTS_FIELD_NAME, KEY_PARTS_FIELD_TYPE)

      // Fill keyParts[i] = Ki.V
      for (i in 0 until KEY_FRAGMENT_COUNT) {
        val fragClassName = "${deobfuscator.type.internalName}\$K$i"
        getStatic(deobType, KEY_PARTS_FIELD_NAME, KEY_PARTS_FIELD_TYPE)
        dup()
        push(i)
        getStatic(Type.getObjectType(fragClassName), "V", INT_ARRAY_FIELD_TYPE)
        arrayStore(INT_ARRAY_TYPE)
      }
      pop()
    }
  }

  private fun ClassVisitor.generateDefaultConstructor() {
    newMethod(ACC_PUBLIC, METHOD_DEFAULT_CONSTRUCTOR) {
      loadThis()
      invokeConstructor(OBJECT_TYPE, METHOD_DEFAULT_CONSTRUCTOR)
    }
  }

  private fun ClassVisitor.generateGetStringMethod() {
    newMethod(ACC_PUBLIC or ACC_STATIC, deobfuscator.deobfuscationMethod) {
      loadArg(0)  // long id
      getStatic(deobfuscator.type.toAsmType(), DATA_FIELD_NAME, DATA_FIELD_TYPE)
      getStatic(deobfuscator.type.toAsmType(), KEY_PARTS_FIELD_NAME, KEY_PARTS_FIELD_TYPE)
      invokeStatic(DEOBFUSCATOR_HELPER_TYPE.toAsmType(), METHOD_GET_STRING)
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Key splitting helpers
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Splits the 32-byte AES key into KEY_FRAGMENT_COUNT int[] arrays.
   * Returns list of IntArrays (one per fragment).
   */
  fun splitKeyIntoFragments(): List<IntArray> {
    require(aesKey.size == 32) { "AES key must be 32 bytes" }
    // 32 bytes / 4 bytes per int = 8 ints total, split into KEY_FRAGMENT_COUNT fragments
    val totalInts = 8  // 32 bytes
    val intsPerFragment = totalInts / KEY_FRAGMENT_COUNT  // e.g. 1 int per fragment if 8 fragments
    val remainder = totalInts % KEY_FRAGMENT_COUNT

    val fragments = mutableListOf<IntArray>()
    var bytePos = 0
    for (i in 0 until KEY_FRAGMENT_COUNT) {
      val fragmentInts = intsPerFragment + if (i < remainder) 1 else 0
      val words = IntArray(fragmentInts)
      for (j in 0 until fragmentInts) {
        words[j] = ((aesKey[bytePos].toInt() and 0xFF) shl 24) or
                   ((aesKey[bytePos + 1].toInt() and 0xFF) shl 16) or
                   ((aesKey[bytePos + 2].toInt() and 0xFF) shl 8) or
                    (aesKey[bytePos + 3].toInt() and 0xFF)
        bytePos += 4
      }
      fragments.add(words)
    }
    return fragments
  }

  companion object {
    // Number of key fragment inner classes (K0 .. K7)
    const val KEY_FRAGMENT_COUNT = 8

    private val METHOD_STATIC_INITIALIZER = Method("<clinit>", "()V")
    private val METHOD_DEFAULT_CONSTRUCTOR = Method("<init>", "()V")

    // Updated signature: (J [[B [[I) Ljava/lang/String;
    private val METHOD_GET_STRING = Method(
      "getString",
      Type.getType(String::class.java),
      arrayOf(Type.LONG_TYPE, Type.getType("[[B"), Type.getType("[[I"))
    )

    private val OBJECT_TYPE = Type.getObjectType("java/lang/Object")

    private const val DATA_FIELD_NAME = "data"
    private val DATA_FIELD_TYPE = Type.getType("[[B")       // byte[][]
    private val BYTE_ARRAY_TYPE = Type.getType("[B")        // byte[]   (array element type)

    private const val KEY_PARTS_FIELD_NAME = "keyParts"
    private val KEY_PARTS_FIELD_TYPE = Type.getType("[[I")  // int[][]
    private val INT_ARRAY_TYPE = Type.getType("[I")         // int[]    (array element type)
    private val INT_ARRAY_FIELD_TYPE = Type.getType("[I")   // int[]    (field descriptor)
  }
}
