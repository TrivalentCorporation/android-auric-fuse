/*
 * Copyright (C) 2006 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.android.server;

import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class AndroidRsaEngine implements AsymmetricBlockCipher {

    private static final String TAG = AndroidRsaEngine.class.getSimpleName();

    private String keyAlias;
    private boolean isSigner;

    private Cipher cipher;
    private KeyStore keyStore;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    private boolean forEncryption;
    private CipherParameters params;

    public AndroidRsaEngine(RSAPublicKey publicKey , RSAPrivateKey privateKey , boolean isSigner) {
        this.isSigner = isSigner;
        try {
            this.cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            this.keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            this.publicKey = publicKey;
            this.privateKey = privateKey;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int getInputBlockSize() {
        int bitSize = publicKey.getModulus().bitLength();

        if (forEncryption) {
            return (bitSize + 7) / 8 - 1;
        } else {
            return (bitSize + 7) / 8;
        }
    }

    @Override
    public int getOutputBlockSize() {
        int bitSize;
        if (publicKey == null && privateKey != null) {
            bitSize = privateKey.getModulus().bitLength();
        } else if (publicKey != null ) {
            bitSize = publicKey.getModulus().bitLength();
        } else {
            throw new NullPointerException("Error keys are null");
        }

        if (forEncryption) {
            return (bitSize + 7) / 8;
        } else {
            return (bitSize + 7) / 8 - 1;
        }
    }

    @Override
    public void init(boolean forEncryption, CipherParameters param) {
        this.forEncryption = forEncryption;
  
        this.params = param;


        try {
            if (forEncryption) {
                cipher.init(Cipher.ENCRYPT_MODE, isSigner ? privateKey: publicKey);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, isSigner ? publicKey: privateKey);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] processBlock(byte[] in, int inOff, int inLen) {
        try {
            byte[] result = cipher.doFinal(in, inOff, inLen);
            byte[] converted = convertOutput(result);
            return converted;
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("Illegal block size: "
                    + e.getMessage());
        } catch (BadPaddingException e) {
            throw new RuntimeException("Bad padding: "
                    + e.getMessage());
        }
    }

    // from BC's RSACoreEngine
    public byte[] convertOutput(byte[] output) {
        if (forEncryption) {
            if (output[0] == 0 && output.length > getOutputBlockSize()) // have ended up with an extra zero byte, copy down.
            {
                byte[] tmp = new byte[output.length - 1];
                System.arraycopy(output, 1, tmp, 0, tmp.length);
                return tmp;
            }

            if (output.length < getOutputBlockSize()) // have ended up with less bytes than normal, lengthen
            {
                byte[] tmp = new byte[getOutputBlockSize()];
                System.arraycopy(output, 0, tmp, tmp.length - output.length, output.length);
                return tmp;
            }
        } else {
            if (output[0] == 0) // have ended up with an extra zero byte, copy down.
            {
                byte[] tmp = new byte[output.length - 1];
                System.arraycopy(output, 1, tmp, 0, tmp.length);
                return tmp;
            }
        }

        return output;
    }


}
