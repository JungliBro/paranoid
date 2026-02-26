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

package io.michaelrocks.paranoid;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Runtime helper that decrypts strings from the encrypted table using AES-256-CTR.
 *
 * The AES key is never stored as a contiguous constant — it is reconstructed
 * at runtime from scattered int[] fragments across generated inner classes.
 * The encrypted string data is stored as a byte[] in the generated Deobfuscator class.
 */
public class DeobfuscatorHelper {

  // Maximum length of each encrypted data chunk (stored as byte[]).
  // Same chunking concept as before, but now byte-based (not char-based).
  public static final int MAX_CHUNK_LENGTH = 0x1fff;

  private DeobfuscatorHelper() {
    // Cannot be instantiated.
  }

  /**
   * Decrypts a single string from the encrypted data table.
   *
   * @param id       Encodes: upper 32 bits = byte offset into the combined table,
   *                 lower 32 bits = encrypted length (in bytes)
   * @param data     The encrypted byte[] chunks concatenated at the Deobfuscator class level
   * @param keyParts The 8 scattered int[] fragments that, concatenated, form the 32-byte AES key
   * @return The decrypted string
   */
  public static String getString(final long id, final byte[][] data, final int[][] keyParts) {
    try {
      final byte[] key = reconstructKey(keyParts);
      final int offset = (int) (id >>> 32);
      final int length = (int) (id & 0xFFFFFFFFL);

      // Extract the encrypted bytes for this string
      final byte[] encrypted = extractBytes(data, offset, length);

      // IV is derived from the offset — deterministic, no need to store separately
      final byte[] iv = makeIv(offset);

      final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
      final byte[] plainBytes = cipher.doFinal(encrypted);

      return new String(plainBytes, "UTF-8");
    } catch (Exception e) {
      // Should never happen with correct key/data — fail silently for release builds
      return "";
    }
  }

  /**
   * Reconstructs the 32-byte AES-256 key from scattered integer fragments.
   * Each int[] in keyParts contributes 4 bytes (big-endian).
   */
  private static byte[] reconstructKey(final int[][] keyParts) {
    final byte[] key = new byte[32];
    int pos = 0;
    for (final int[] part : keyParts) {
      for (final int word : part) {
        if (pos >= 32) break;
        key[pos++] = (byte) (word >>> 24);
        key[pos++] = (byte) (word >>> 16);
        key[pos++] = (byte) (word >>> 8);
        key[pos++] = (byte) word;
      }
    }
    return key;
  }

  /**
   * Extracts `length` bytes starting at `offset` from the chunked byte[][] table.
   */
  private static byte[] extractBytes(final byte[][] chunks, final int offset, final int length) {
    final byte[] result = new byte[length];
    int remaining = length;
    int outputPos = 0;
    int globalPos = offset;

    while (remaining > 0) {
      final int chunkIndex = globalPos / MAX_CHUNK_LENGTH;
      final int chunkOffset = globalPos % MAX_CHUNK_LENGTH;
      final int available = Math.min(chunks[chunkIndex].length - chunkOffset, remaining);
      System.arraycopy(chunks[chunkIndex], chunkOffset, result, outputPos, available);
      outputPos += available;
      globalPos += available;
      remaining -= available;
    }
    return result;
  }

  /**
   * Derives a 16-byte AES-CTR IV from the string's byte offset.
   * Deterministic — the offset uniquely identifies each string so no IV storage needed.
   */
  private static byte[] makeIv(final int offset) {
    final byte[] iv = new byte[16];
    iv[0]  = (byte) (offset >>> 24);
    iv[1]  = (byte) (offset >>> 16);
    iv[2]  = (byte) (offset >>> 8);
    iv[3]  = (byte) offset;
    // Remaining bytes stay 0 — offset gives enough uniqueness per string position
    return iv;
  }
}
