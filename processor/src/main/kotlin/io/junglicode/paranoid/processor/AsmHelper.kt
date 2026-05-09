package io.junglicode.paranoid.processor

import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Opcodes.*

object AsmHelper {

  fun generate_getString(cv: ClassVisitor, internalName: String) {
    val mv = cv.visitMethod(ACC_PUBLIC or ACC_STATIC, "getString", "(J[[B[[I)Ljava/lang/String;", null, null)
    mv.visitCode();
    val label0 = Label()
    val label1 = Label()
    val label2 = Label()
    mv.visitTryCatchBlock(label0, label1, label2, "java/lang/Exception");
    mv.visitLabel(label0);
    mv.visitLineNumber(52, label0);
    mv.visitVarInsn(ALOAD, 3);
    mv.visitMethodInsn(INVOKESTATIC, internalName, "reconstructKey", "([[I)[B", false);
    mv.visitVarInsn(ASTORE, 4);
    val label3 = Label()
    mv.visitLabel(label3);
    mv.visitLineNumber(53, label3);
    mv.visitVarInsn(LLOAD, 0);
    mv.visitIntInsn(BIPUSH, 32);
    mv.visitInsn(LUSHR);
    mv.visitInsn(L2I);
    mv.visitVarInsn(ISTORE, 5);
    val label4 = Label()
    mv.visitLabel(label4);
    mv.visitLineNumber(54, label4);
    mv.visitVarInsn(LLOAD, 0);
    mv.visitLdcInsn(4294967295L);
    mv.visitInsn(LAND);
    mv.visitInsn(L2I);
    mv.visitVarInsn(ISTORE, 6);
    val label5 = Label()
    mv.visitLabel(label5);
    mv.visitLineNumber(57, label5);
    mv.visitVarInsn(ALOAD, 2);
    mv.visitVarInsn(ILOAD, 5);
    mv.visitVarInsn(ILOAD, 6);
    mv.visitMethodInsn(INVOKESTATIC, internalName, "extractBytes", "([[BII)[B", false);
    mv.visitVarInsn(ASTORE, 7);
    val label6 = Label()
    mv.visitLabel(label6);
    mv.visitLineNumber(60, label6);
    mv.visitVarInsn(ILOAD, 5);
    mv.visitMethodInsn(INVOKESTATIC, internalName, "makeIv", "(I)[B", false);
    mv.visitVarInsn(ASTORE, 8);
    val label7 = Label()
    mv.visitLabel(label7);
    mv.visitLineNumber(62, label7);
    mv.visitLdcInsn("AES/CTR/NoPadding");
    mv.visitMethodInsn(INVOKESTATIC, "javax/crypto/Cipher", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", false);
    mv.visitVarInsn(ASTORE, 9);
    val label8 = Label()
    mv.visitLabel(label8);
    mv.visitLineNumber(63, label8);
    mv.visitVarInsn(ALOAD, 9);
    mv.visitInsn(ICONST_2);
    mv.visitTypeInsn(NEW, "javax/crypto/spec/SecretKeySpec");
    mv.visitInsn(DUP);
    mv.visitVarInsn(ALOAD, 4);
    mv.visitLdcInsn("AES");
    mv.visitMethodInsn(INVOKESPECIAL, "javax/crypto/spec/SecretKeySpec", "<init>", "([BLjava/lang/String;)V", false);
    mv.visitTypeInsn(NEW, "javax/crypto/spec/IvParameterSpec");
    mv.visitInsn(DUP);
    mv.visitVarInsn(ALOAD, 8);
    mv.visitMethodInsn(INVOKESPECIAL, "javax/crypto/spec/IvParameterSpec", "<init>", "([B)V", false);
    mv.visitMethodInsn(INVOKEVIRTUAL, "javax/crypto/Cipher", "init", "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V", false);
    val label9 = Label()
    mv.visitLabel(label9);
    mv.visitLineNumber(64, label9);
    mv.visitVarInsn(ALOAD, 9);
    mv.visitVarInsn(ALOAD, 7);
    mv.visitMethodInsn(INVOKEVIRTUAL, "javax/crypto/Cipher", "doFinal", "([B)[B", false);
    mv.visitVarInsn(ASTORE, 10);
    val label10 = Label()
    mv.visitLabel(label10);
    mv.visitLineNumber(66, label10);
    mv.visitTypeInsn(NEW, "java/lang/String");
    mv.visitInsn(DUP);
    mv.visitVarInsn(ALOAD, 10);
    mv.visitLdcInsn("UTF-8");
    mv.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([BLjava/lang/String;)V", false);
    mv.visitLabel(label1);
    mv.visitInsn(ARETURN);
    mv.visitLabel(label2);
    mv.visitLineNumber(67, label2);
    mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, arrayOf("java/lang/Exception"));
    mv.visitVarInsn(ASTORE, 4);
    val label11 = Label()
    mv.visitLabel(label11);
    mv.visitLineNumber(69, label11);
    mv.visitLdcInsn("");
    mv.visitInsn(ARETURN);
    val label12 = Label()
    mv.visitLabel(label12);
    mv.visitLocalVariable("key", "[B", null, label3, label2, 4);
    mv.visitLocalVariable("offset", "I", null, label4, label2, 5);
    mv.visitLocalVariable("length", "I", null, label5, label2, 6);
    mv.visitLocalVariable("encrypted", "[B", null, label6, label2, 7);
    mv.visitLocalVariable("iv", "[B", null, label7, label2, 8);
    mv.visitLocalVariable("cipher", "Ljavax/crypto/Cipher;", null, label8, label2, 9);
    mv.visitLocalVariable("plainBytes", "[B", null, label10, label2, 10);
    mv.visitLocalVariable("e", "Ljava/lang/Exception;", null, label11, label12, 4);
    mv.visitLocalVariable("id", "J", null, label0, label12, 0);
    mv.visitLocalVariable("data", "[[B", null, label0, label12, 2);
    mv.visitLocalVariable("keyParts", "[[I", null, label0, label12, 3);
    mv.visitMaxs(6, 11);
    mv.visitEnd();
  }

  fun generate_reconstructKey(cv: ClassVisitor, internalName: String) {
    val mv = cv.visitMethod(ACC_PRIVATE or ACC_STATIC, "reconstructKey", "([[I)[B", null, null)
    mv.visitCode();
    val label0 = Label()
    mv.visitLabel(label0);
    mv.visitLineNumber(78, label0);
    mv.visitIntInsn(BIPUSH, 32);
    mv.visitIntInsn(NEWARRAY, T_BYTE);
    mv.visitVarInsn(ASTORE, 1);
    val label1 = Label()
    mv.visitLabel(label1);
    mv.visitLineNumber(79, label1);
    mv.visitInsn(ICONST_0);
    mv.visitVarInsn(ISTORE, 2);
    val label2 = Label()
    mv.visitLabel(label2);
    mv.visitLineNumber(80, label2);
    mv.visitVarInsn(ALOAD, 0);
    mv.visitVarInsn(ASTORE, 3);
    mv.visitVarInsn(ALOAD, 3);
    mv.visitInsn(ARRAYLENGTH);
    mv.visitVarInsn(ISTORE, 4);
    mv.visitInsn(ICONST_0);
    mv.visitVarInsn(ISTORE, 5);
    val label3 = Label()
    mv.visitLabel(label3);
    mv.visitFrame(Opcodes.F_FULL, 6, arrayOf("[[I", "[B", Opcodes.INTEGER, "[[I", Opcodes.INTEGER, Opcodes.INTEGER), 0, emptyArray<Any>())
    mv.visitVarInsn(ILOAD, 5);
    mv.visitVarInsn(ILOAD, 4);
    val label4 = Label()
    mv.visitJumpInsn(IF_ICMPGE, label4);
    mv.visitVarInsn(ALOAD, 3);
    mv.visitVarInsn(ILOAD, 5);
    mv.visitInsn(AALOAD);
    mv.visitVarInsn(ASTORE, 6);
    val label5 = Label()
    mv.visitLabel(label5);
    mv.visitLineNumber(81, label5);
    mv.visitVarInsn(ALOAD, 6);
    mv.visitVarInsn(ASTORE, 7);
    mv.visitVarInsn(ALOAD, 7);
    mv.visitInsn(ARRAYLENGTH);
    mv.visitVarInsn(ISTORE, 8);
    mv.visitInsn(ICONST_0);
    mv.visitVarInsn(ISTORE, 9);
    val label6 = Label()
    mv.visitLabel(label6);
    mv.visitFrame(Opcodes.F_FULL, 10, arrayOf("[[I", "[B", Opcodes.INTEGER, "[[I", Opcodes.INTEGER, Opcodes.INTEGER, "[I", "[I", Opcodes.INTEGER, Opcodes.INTEGER), 0, emptyArray<Any>())
    mv.visitVarInsn(ILOAD, 9);
    mv.visitVarInsn(ILOAD, 8);
    val label7 = Label()
    mv.visitJumpInsn(IF_ICMPGE, label7);
    mv.visitVarInsn(ALOAD, 7);
    mv.visitVarInsn(ILOAD, 9);
    mv.visitInsn(IALOAD);
    mv.visitVarInsn(ISTORE, 10);
    val label8 = Label()
    mv.visitLabel(label8);
    mv.visitLineNumber(82, label8);
    mv.visitVarInsn(ILOAD, 2);
    mv.visitIntInsn(BIPUSH, 32);
    val label9 = Label()
    mv.visitJumpInsn(IF_ICMPLT, label9);
    mv.visitJumpInsn(GOTO, label7);
    mv.visitLabel(label9);
    mv.visitLineNumber(83, label9);
    mv.visitFrame(Opcodes.F_APPEND,1, arrayOf(Opcodes.INTEGER), 0, null);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitVarInsn(ILOAD, 2);
    mv.visitIincInsn(2, 1);
    mv.visitVarInsn(ILOAD, 10);
    mv.visitIntInsn(BIPUSH, 24);
    mv.visitInsn(IUSHR);
    mv.visitInsn(I2B);
    mv.visitInsn(BASTORE);
    val label10 = Label()
    mv.visitLabel(label10);
    mv.visitLineNumber(84, label10);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitVarInsn(ILOAD, 2);
    mv.visitIincInsn(2, 1);
    mv.visitVarInsn(ILOAD, 10);
    mv.visitIntInsn(BIPUSH, 16);
    mv.visitInsn(IUSHR);
    mv.visitInsn(I2B);
    mv.visitInsn(BASTORE);
    val label11 = Label()
    mv.visitLabel(label11);
    mv.visitLineNumber(85, label11);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitVarInsn(ILOAD, 2);
    mv.visitIincInsn(2, 1);
    mv.visitVarInsn(ILOAD, 10);
    mv.visitIntInsn(BIPUSH, 8);
    mv.visitInsn(IUSHR);
    mv.visitInsn(I2B);
    mv.visitInsn(BASTORE);
    val label12 = Label()
    mv.visitLabel(label12);
    mv.visitLineNumber(86, label12);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitVarInsn(ILOAD, 2);
    mv.visitIincInsn(2, 1);
    mv.visitVarInsn(ILOAD, 10);
    mv.visitInsn(I2B);
    mv.visitInsn(BASTORE);
    val label13 = Label()
    mv.visitLabel(label13);
    mv.visitLineNumber(81, label13);
    mv.visitIincInsn(9, 1);
    mv.visitJumpInsn(GOTO, label6);
    mv.visitLabel(label7);
    mv.visitLineNumber(80, label7);
    mv.visitFrame(Opcodes.F_FULL, 6, arrayOf("[[I", "[B", Opcodes.INTEGER, "[[I", Opcodes.INTEGER, Opcodes.INTEGER), 0, emptyArray<Any>())
    mv.visitIincInsn(5, 1);
    mv.visitJumpInsn(GOTO, label3);
    mv.visitLabel(label4);
    mv.visitLineNumber(89, label4);
    mv.visitFrame(Opcodes.F_CHOP,3, null, 0, null);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitInsn(ARETURN);
    val label14 = Label()
    mv.visitLabel(label14);
    mv.visitLocalVariable("word", "I", null, label8, label13, 10);
    mv.visitLocalVariable("part", "[I", null, label5, label7, 6);
    mv.visitLocalVariable("keyParts", "[[I", null, label0, label14, 0);
    mv.visitLocalVariable("key", "[B", null, label1, label14, 1);
    mv.visitLocalVariable("pos", "I", null, label2, label14, 2);
    mv.visitMaxs(4, 11);
    mv.visitEnd();
  }

  fun generate_extractBytes(cv: ClassVisitor, internalName: String) {
    val mv = cv.visitMethod(ACC_PRIVATE or ACC_STATIC, "extractBytes", "([[BII)[B", null, null)
    mv.visitCode();
    val label0 = Label()
    mv.visitLabel(label0);
    mv.visitLineNumber(96, label0);
    mv.visitVarInsn(ILOAD, 2);
    mv.visitIntInsn(NEWARRAY, T_BYTE);
    mv.visitVarInsn(ASTORE, 3);
    val label1 = Label()
    mv.visitLabel(label1);
    mv.visitLineNumber(97, label1);
    mv.visitVarInsn(ILOAD, 2);
    mv.visitVarInsn(ISTORE, 4);
    val label2 = Label()
    mv.visitLabel(label2);
    mv.visitLineNumber(98, label2);
    mv.visitInsn(ICONST_0);
    mv.visitVarInsn(ISTORE, 5);
    val label3 = Label()
    mv.visitLabel(label3);
    mv.visitLineNumber(99, label3);
    mv.visitVarInsn(ILOAD, 1);
    mv.visitVarInsn(ISTORE, 6);
    val label4 = Label()
    mv.visitLabel(label4);
    mv.visitLineNumber(101, label4);
    mv.visitFrame(Opcodes.F_FULL, 7, arrayOf("[[B", Opcodes.INTEGER, Opcodes.INTEGER, "[B", Opcodes.INTEGER, Opcodes.INTEGER, Opcodes.INTEGER), 0, emptyArray<Any>())
    mv.visitVarInsn(ILOAD, 4);
    val label5 = Label()
    mv.visitJumpInsn(IFLE, label5);
    val label6 = Label()
    mv.visitLabel(label6);
    mv.visitLineNumber(102, label6);
    mv.visitVarInsn(ILOAD, 6);
    mv.visitIntInsn(SIPUSH, 1024);
    mv.visitInsn(IDIV);
    mv.visitVarInsn(ISTORE, 7);
    val label7 = Label()
    mv.visitLabel(label7);
    mv.visitLineNumber(103, label7);
    mv.visitVarInsn(ILOAD, 6);
    mv.visitIntInsn(SIPUSH, 1024);
    mv.visitInsn(IREM);
    mv.visitVarInsn(ISTORE, 8);
    val label8 = Label()
    mv.visitLabel(label8);
    mv.visitLineNumber(104, label8);
    mv.visitVarInsn(ALOAD, 0);
    mv.visitVarInsn(ILOAD, 7);
    mv.visitInsn(AALOAD);
    mv.visitInsn(ARRAYLENGTH);
    mv.visitVarInsn(ILOAD, 8);
    mv.visitInsn(ISUB);
    mv.visitVarInsn(ILOAD, 4);
    mv.visitMethodInsn(INVOKESTATIC, "java/lang/Math", "min", "(II)I", false);
    mv.visitVarInsn(ISTORE, 9);
    val label9 = Label()
    mv.visitLabel(label9);
    mv.visitLineNumber(105, label9);
    mv.visitVarInsn(ALOAD, 0);
    mv.visitVarInsn(ILOAD, 7);
    mv.visitInsn(AALOAD);
    mv.visitVarInsn(ILOAD, 8);
    mv.visitVarInsn(ALOAD, 3);
    mv.visitVarInsn(ILOAD, 5);
    mv.visitVarInsn(ILOAD, 9);
    mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V", false);
    val label10 = Label()
    mv.visitLabel(label10);
    mv.visitLineNumber(106, label10);
    mv.visitVarInsn(ILOAD, 5);
    mv.visitVarInsn(ILOAD, 9);
    mv.visitInsn(IADD);
    mv.visitVarInsn(ISTORE, 5);
    val label11 = Label()
    mv.visitLabel(label11);
    mv.visitLineNumber(107, label11);
    mv.visitVarInsn(ILOAD, 6);
    mv.visitVarInsn(ILOAD, 9);
    mv.visitInsn(IADD);
    mv.visitVarInsn(ISTORE, 6);
    val label12 = Label()
    mv.visitLabel(label12);
    mv.visitLineNumber(108, label12);
    mv.visitVarInsn(ILOAD, 4);
    mv.visitVarInsn(ILOAD, 9);
    mv.visitInsn(ISUB);
    mv.visitVarInsn(ISTORE, 4);
    val label13 = Label()
    mv.visitLabel(label13);
    mv.visitLineNumber(109, label13);
    mv.visitJumpInsn(GOTO, label4);
    mv.visitLabel(label5);
    mv.visitLineNumber(110, label5);
    mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
    mv.visitVarInsn(ALOAD, 3);
    mv.visitInsn(ARETURN);
    val label14 = Label()
    mv.visitLabel(label14);
    mv.visitLocalVariable("chunkIndex", "I", null, label7, label13, 7);
    mv.visitLocalVariable("chunkOffset", "I", null, label8, label13, 8);
    mv.visitLocalVariable("available", "I", null, label9, label13, 9);
    mv.visitLocalVariable("chunks", "[[B", null, label0, label14, 0);
    mv.visitLocalVariable("offset", "I", null, label0, label14, 1);
    mv.visitLocalVariable("length", "I", null, label0, label14, 2);
    mv.visitLocalVariable("result", "[B", null, label1, label14, 3);
    mv.visitLocalVariable("remaining", "I", null, label2, label14, 4);
    mv.visitLocalVariable("outputPos", "I", null, label3, label14, 5);
    mv.visitLocalVariable("globalPos", "I", null, label4, label14, 6);
    mv.visitMaxs(5, 10);
    mv.visitEnd();
  }

  fun generate_makeIv(cv: ClassVisitor, internalName: String) {
    val mv = cv.visitMethod(ACC_PRIVATE or ACC_STATIC, "makeIv", "(I)[B", null, null)
    mv.visitCode();
    val label0 = Label()
    mv.visitLabel(label0);
    mv.visitLineNumber(118, label0);
    mv.visitIntInsn(BIPUSH, 16);
    mv.visitIntInsn(NEWARRAY, T_BYTE);
    mv.visitVarInsn(ASTORE, 1);
    val label1 = Label()
    mv.visitLabel(label1);
    mv.visitLineNumber(119, label1);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitInsn(ICONST_0);
    mv.visitVarInsn(ILOAD, 0);
    mv.visitIntInsn(BIPUSH, 24);
    mv.visitInsn(IUSHR);
    mv.visitInsn(I2B);
    mv.visitInsn(BASTORE);
    val label2 = Label()
    mv.visitLabel(label2);
    mv.visitLineNumber(120, label2);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitInsn(ICONST_1);
    mv.visitVarInsn(ILOAD, 0);
    mv.visitIntInsn(BIPUSH, 16);
    mv.visitInsn(IUSHR);
    mv.visitInsn(I2B);
    mv.visitInsn(BASTORE);
    val label3 = Label()
    mv.visitLabel(label3);
    mv.visitLineNumber(121, label3);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitInsn(ICONST_2);
    mv.visitVarInsn(ILOAD, 0);
    mv.visitIntInsn(BIPUSH, 8);
    mv.visitInsn(IUSHR);
    mv.visitInsn(I2B);
    mv.visitInsn(BASTORE);
    val label4 = Label()
    mv.visitLabel(label4);
    mv.visitLineNumber(122, label4);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitInsn(ICONST_3);
    mv.visitVarInsn(ILOAD, 0);
    mv.visitInsn(I2B);
    mv.visitInsn(BASTORE);
    val label5 = Label()
    mv.visitLabel(label5);
    mv.visitLineNumber(124, label5);
    mv.visitVarInsn(ALOAD, 1);
    mv.visitInsn(ARETURN);
    val label6 = Label()
    mv.visitLabel(label6);
    mv.visitLocalVariable("offset", "I", null, label0, label6, 0);
    mv.visitLocalVariable("iv", "[B", null, label1, label6, 1);
    mv.visitMaxs(4, 2);
    mv.visitEnd();
  }
}
