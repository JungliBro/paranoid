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

import io.junglicode.paranoid.DeobfuscatorHelper
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

interface StringRegistry {
  fun registerString(string: String): Long
  fun getAllEncryptedBytes(): ByteArray
  fun getChunkCount(): Int
  fun getChunkBytes(index: Int): ByteArray
}

/**
 * AES-256-CTR based string registry.
 *
 * Each string is UTF-8 encoded, then AES-256-CTR encrypted (NoPadding) using:
 *   - The shared AES key (32 bytes, generated once per build by ParanoidProcessor)
 *   - A deterministic IV derived from the current byte offset in the table
 *
 * The returned ID encodes:
 *   - Upper 32 bits: byte offset into the encrypted table
 *   - Lower 32 bits: encrypted byte length
 */
class StringRegistryImpl(private val aesKey: ByteArray) : StringRegistry {

  private val encryptedTable = mutableListOf<Byte>()

  init {
    require(aesKey.size == 32) { "AES key must be 32 bytes (256-bit), got ${aesKey.size}" }
  }

  override fun registerString(string: String): Long {
    val plainBytes = string.toByteArray(Charsets.UTF_8)
    val offset = encryptedTable.size

    val iv = makeIv(offset)
    val cipher = Cipher.getInstance("AES/CTR/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"), IvParameterSpec(iv))
    val encrypted = cipher.doFinal(plainBytes)

    encryptedTable.addAll(encrypted.toList())

    // Pack offset (upper 32) + length (lower 32) into a Long ID
    return (offset.toLong() shl 32) or (encrypted.size.toLong() and 0xFFFFFFFFL)
  }

  override fun getAllEncryptedBytes(): ByteArray = encryptedTable.toByteArray()

  override fun getChunkCount(): Int {
    val total = encryptedTable.size
    return if (total == 0) 1 else (total + DeobfuscatorHelper.MAX_CHUNK_LENGTH - 1) / DeobfuscatorHelper.MAX_CHUNK_LENGTH
  }

  override fun getChunkBytes(index: Int): ByteArray {
    val all = encryptedTable.toByteArray()
    val start = index * DeobfuscatorHelper.MAX_CHUNK_LENGTH
    val end = minOf(start + DeobfuscatorHelper.MAX_CHUNK_LENGTH, all.size)
    return if (start >= all.size) ByteArray(0) else all.copyOfRange(start, end)
  }

  private fun makeIv(offset: Int): ByteArray {
    val iv = ByteArray(16)
    iv[0] = (offset ushr 24).toByte()
    iv[1] = (offset ushr 16).toByte()
    iv[2] = (offset ushr 8).toByte()
    iv[3] = offset.toByte()
    return iv
  }
}
