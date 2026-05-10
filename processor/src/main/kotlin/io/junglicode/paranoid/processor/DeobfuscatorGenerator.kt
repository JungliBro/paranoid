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
import org.objectweb.asm.commons.GeneratorAdapter
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
    writer.generateKeyField()
    writer.generateStaticInitializer()
    writer.generateDefaultConstructor()

    // Generate the inline helper methods for decryption (from AsmHelper)
    AsmHelper.generate_extractBytes(writer, deobfuscator.type.internalName)
    AsmHelper.generate_makeIv(writer, deobfuscator.type.internalName)
    
    // Generate the getString method that uses the inline helpers
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

  private fun ClassVisitor.generateKeyField() {
    visitField(ACC_PRIVATE or ACC_STATIC or ACC_FINAL, KEY_FIELD_NAME, KEY_FIELD_TYPE.descriptor, null, null).visitEnd()
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Static initializer — fills data[][] with encrypted bytes
  // ──────────────────────────────────────────────────────────────────────────

  private fun ClassVisitor.generateStaticInitializer() {
    val chunkCount = stringRegistry.getChunkCount()
    val deobType = deobfuscator.type.toAsmType()

    newMethod(Opcodes.ACC_STATIC, METHOD_STATIC_INITIALIZER) {
      // data = new byte[chunkCount][]
      push(chunkCount)
      newArray(BYTE_ARRAY_TYPE)
      putStatic(deobType, DATA_FIELD_NAME, DATA_FIELD_TYPE)

      // Fill each chunk via separate methods to avoid "Method too large"
      for (i in 0 until chunkCount) {
        getStatic(deobType, DATA_FIELD_NAME, DATA_FIELD_TYPE)
        invokeStatic(deobType, Method("fill$i", "([[B)V"))
      }

      // Fill key field directly in clinit
      push(32)
      newArray(Type.BYTE_TYPE)
      aesKey.forEachIndexed { index, byte ->
        dup()
        push(index)
        push(byte.toInt())
        arrayStore(Type.BYTE_TYPE)
      }
      putStatic(deobType, KEY_FIELD_NAME, KEY_FIELD_TYPE)
    }

    // Generate the fill methods
    for (i in 0 until chunkCount) {
      val chunkBytes = stringRegistry.getChunkBytes(i)
      newMethod(ACC_PRIVATE or ACC_STATIC, Method("fill$i", "([[B)V")) {
        loadArg(0) // the byte[][] data
        push(i)
        push(chunkBytes.size)
        newArray(Type.BYTE_TYPE)
        chunkBytes.forEachIndexed { byteIdx, byte ->
          dup()
          push(byteIdx)
          push(byte.toInt())
          arrayStore(Type.BYTE_TYPE)
        }
        arrayStore(BYTE_ARRAY_TYPE)
      }
    }
  }

  private fun ClassVisitor.generateGetStringMethod() {
    newMethod(ACC_PUBLIC or ACC_STATIC, deobfuscator.deobfuscationMethod) {
      val start = newLabel()
      val end = newLabel()
      val catchBlock = newLabel()
      visitTryCatchBlock(start, end, catchBlock, "java/lang/Exception")
      mark(start)
      
      // offset = (int) (id >>> 32)
      loadArg(0)
      push(32)
      math(GeneratorAdapter.USHR, Type.LONG_TYPE)
      cast(Type.LONG_TYPE, Type.INT_TYPE)
      val offsetLocal = newLocal(Type.INT_TYPE)
      storeLocal(offsetLocal)
      
      // length = (int) (id & 0xFFFFFFFFL)
      loadArg(0)
      push(4294967295L)
      math(GeneratorAdapter.AND, Type.LONG_TYPE)
      cast(Type.LONG_TYPE, Type.INT_TYPE)
      val lengthLocal = newLocal(Type.INT_TYPE)
      storeLocal(lengthLocal)
      
      // encrypted = extractBytes(data, offset, length)
      getStatic(deobfuscator.type.toAsmType(), DATA_FIELD_NAME, DATA_FIELD_TYPE)
      loadLocal(offsetLocal)
      loadLocal(lengthLocal)
      invokeStatic(deobfuscator.type.toAsmType(), Method("extractBytes", "([[BII)[B"))
      val encryptedLocal = newLocal(Type.getType("[B"))
      storeLocal(encryptedLocal)
      
      // iv = makeIv(offset)
      loadLocal(offsetLocal)
      invokeStatic(deobfuscator.type.toAsmType(), Method("makeIv", "(I)[B"))
      val ivLocal = newLocal(Type.getType("[B"))
      storeLocal(ivLocal)
      
      // cipher = Cipher.getInstance("AES/CTR/NoPadding")
      push("AES/CTR/NoPadding")
      invokeStatic(Type.getType(javax.crypto.Cipher::class.java), Method("getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;"))
      val cipherLocal = newLocal(Type.getType(javax.crypto.Cipher::class.java))
      storeLocal(cipherLocal)
      
      // cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv))
      loadLocal(cipherLocal)
      push(javax.crypto.Cipher.DECRYPT_MODE)
      
      newInstance(Type.getType(javax.crypto.spec.SecretKeySpec::class.java))
      dup()
      getStatic(deobfuscator.type.toAsmType(), KEY_FIELD_NAME, KEY_FIELD_TYPE)
      push("AES")
      invokeConstructor(Type.getType(javax.crypto.spec.SecretKeySpec::class.java), Method("<init>", "([BLjava/lang/String;)V"))
      
      newInstance(Type.getType(javax.crypto.spec.IvParameterSpec::class.java))
      dup()
      loadLocal(ivLocal)
      invokeConstructor(Type.getType(javax.crypto.spec.IvParameterSpec::class.java), Method("<init>", "([B)V"))
      
      invokeVirtual(Type.getType(javax.crypto.Cipher::class.java), Method("init", "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V"))
      
      // plainBytes = cipher.doFinal(encrypted)
      loadLocal(cipherLocal)
      loadLocal(encryptedLocal)
      invokeVirtual(Type.getType(javax.crypto.Cipher::class.java), Method("doFinal", "([B)[B"))
      val plainBytesLocal = newLocal(Type.getType("[B"))
      storeLocal(plainBytesLocal)
      
      // return new String(plainBytes, "UTF-8")
      newInstance(Type.getType(String::class.java))
      dup()
      loadLocal(plainBytesLocal)
      push("UTF-8")
      invokeConstructor(Type.getType(String::class.java), Method("<init>", "([BLjava/lang/String;)V"))
      returnValue()
      
      mark(end)
      
      mark(catchBlock)
      // return ""
      push("")
      returnValue()
    }
  }

  private fun ClassVisitor.generateDefaultConstructor() {
    newMethod(ACC_PUBLIC, METHOD_DEFAULT_CONSTRUCTOR) {
      loadThis()
      invokeConstructor(OBJECT_TYPE, METHOD_DEFAULT_CONSTRUCTOR)
    }
  }

  companion object {
    private val METHOD_STATIC_INITIALIZER = Method("<clinit>", "()V")
    private val METHOD_DEFAULT_CONSTRUCTOR = Method("<init>", "()V")

    private val OBJECT_TYPE = Type.getObjectType("java/lang/Object")

    private const val DATA_FIELD_NAME = "data"
    private val DATA_FIELD_TYPE = Type.getType("[[B")       // byte[][]
    private val BYTE_ARRAY_TYPE = Type.getType("[B")        // byte[]   (array element type)
    private const val KEY_FIELD_NAME = "key"
    private val KEY_FIELD_TYPE = Type.getType("[B")         // byte[]
  }
}
