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

package android.os;

import android.content.Context;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Log;

/*
This is a class that is SDK-facing for our Management Service to use to communicate via AIDL with the Auric system service
*/
public final class AuricManager {

    private static final String TAG = "AuricManager";

    private static final AuricManager instance = new AuricManager();

    private final IAuricService mService;

    // This is a singleton
    public static AuricManager getInstance() {
        return instance;
    }

    /**
     * @hide to prevent subclassing from outside of the framework
     */
    private AuricManager() {
        mService = IAuricService.Stub.asInterface(ServiceManager.getService(Context.AURIC_SERVICE));
    }

    public byte[] getPublicKey() {
		try {
			return mService.getPublicKey();
		}
		catch (Exception e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
			System.out.println(e.toString());
			return null;
		}
    }
	
    public byte[] initializeCrypto(int m, int n, byte[] wrappedKey, boolean loggingEnabled) {
        try {
            return mService.initializeCrypto(m, n, wrappedKey, loggingEnabled);
        }
        catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
            System.out.println(e.toString());
            return null;
        }
    }

    public byte[] deauthenticate() {
        try {
            return mService.deauthenticate();
        }
        catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
            System.out.println(e.toString());
            return null;
        }
    }

    public byte[] reauthenticate(byte[] wrappedKey) {
        try {
            return mService.reauthenticate(wrappedKey);
        }
        catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
            System.out.println(e.toString());
            return null;
        }
    }


    public boolean sendEncryptedDirectory(String encryptedDir, boolean persistDirConfig) {
		try {
			return mService.sendEncryptedDirectory(encryptedDir, persistDirConfig);
		}
		catch (Exception e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
			System.out.println(e.toString());
			return false;
		}
    }
    

}

