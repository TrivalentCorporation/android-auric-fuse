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

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import java.security.interfaces.RSAPrivateKey;
import java.security.Key;
import org.bouncycastle.crypto.digests.SHA512Digest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyWrapping {

    private static String RSAAlgorithm = "RSA/ECB/PKCS1Padding";
    private static String AESWrapAlgorithm ="AESWrap";

    public Key asymmetricUnwrapKey(Key keyToUnwrap, Key rsaPrivateKey) {
        try {
            AndroidRsaEngine rsa = new AndroidRsaEngine(null, (RSAPrivateKey) rsaPrivateKey, false);

            Digest digest = new SHA512Digest();
            OAEPEncoding oaep = new OAEPEncoding(rsa, digest, null);

            oaep.init(false, null);
            byte[] plainText = oaep.processBlock(keyToUnwrap.getEncoded(), 0, keyToUnwrap.getEncoded().length);

            SecretKey actualKey = new SecretKeySpec(plainText, 0 , plainText.length, "AES");
            Arrays.fill(plainText, (byte)0x00);

            return actualKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }

}
