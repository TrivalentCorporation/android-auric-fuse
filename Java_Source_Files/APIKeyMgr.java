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

import android.content.Context;
import java.security.KeyStore;
import java.util.Calendar;
import java.util.Date;
import android.security.KeyPairGeneratorSpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.math.BigInteger;
import android.util.Log;
import javax.security.auth.x500.X500Principal;

public class APIKeyMgr {

    /**RSA Key File names*/
    private static String PUBLIC_KEY = "public.cer";

    private Context context;
    private String alias = "";

    public APIKeyMgr(Context applicationContext, String alias) {
        this.context = applicationContext;
        this.alias = alias;
    }

    /**
     * Retrieve a public RSA asymetric key.  If one is not already generated and saved, create a new public/private key pair
     * @return
     */
    public PublicKey getPublicKey(boolean forceKeyRegen)
    {
        KeyStore ks;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null, null);
            KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, null);

            if (keyEntry == null || forceKeyRegen) {

                Calendar cal = Calendar.getInstance();
                Date now = cal.getTime();
                cal.add(Calendar.YEAR, 1);
                Date end = cal.getTime();

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                kpg.initialize(new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(alias)
                        .setStartDate(now)
                        .setEndDate(end)
                        .setSerialNumber(BigInteger.valueOf(1))
                        .setSubject(new X500Principal("CN=test1"))
                        .build());

                KeyPair kp = kpg.generateKeyPair();

                return kp.getPublic();
            } else {
                return keyEntry.getCertificate().getPublicKey();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } 
        
        return null;
    }

    public PrivateKey getPrivateKey() {
        KeyStore ks;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null, null);
            KeyStore.Entry keyEntry = ks.getEntry(alias, null);

            if (keyEntry == null || !(keyEntry instanceof KeyStore.PrivateKeyEntry)) {
                //Will gen the key pair
                getPublicKey(false);
                keyEntry = ks.getEntry(alias, null);
                if (keyEntry == null) {
                    return null;
                }
                else {

                    return ((KeyStore.PrivateKeyEntry) keyEntry).getPrivateKey();
                }
            } else {
                return ((KeyStore.PrivateKeyEntry) keyEntry).getPrivateKey();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }


}
