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
import android.security.AndroidKeyStoreProvider;
import android.os.IAuricService;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import android.util.Slog;
import java.util.Arrays;
import java.util.Properties;
import java.security.PublicKey;
import java.security.Security;
import java.security.Provider;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import android.os.Environment;
import android.os.UserHandle;

import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import co.trivalent.auricutils.AuricUtils;

/**
 * Keeps the lock pattern/password data and related settings for each user.
 * Used by LockPatternUtils. Needs to be a service because Settings app also needs
 * to be able to save lockscreen information for secondary users.
 * @hide
 */
public class AuricService extends IAuricService.Stub {

    private static final String TAG = "AuricService";

    private final Context mContext;
    private final AuricDaemonConnection mConnection;
    private APIKeyMgr keyMgr;

    private static final String AURICFS_ADMIN_PERM = android.Manifest.permission.AURICFS_ADMIN;

    ////////////////////////// Daemon Connection related fields ////////////////////////
    // See AuricDaemonConnection for more info regarding these commands
    public static final short INITIALIZE = 10;
    public static final short DEAUTHENTICATE = 11;
    public static final short REAUTHENTICATE = 12;
    public static final short REINITIALIZE = 13;
    public static final short SEND_EMULATED_SD_PATH = 14;
    public static final short SEND_ENCRYPTED_DIR = 15;

    public static final short SUCCESS_RESPONSE = 100;
    public static final short FAILURE_RESPONSE = 101;

    ///////////////////////////////////////////////////////////////////////////////////////

    ////////////////////////// Log related fields ////////////////////////
    private static final String FILE_DATE = "yyyyMMddHHmmss";
    private static final String LOG_DATE = "yyyy/MM/dd HH:mm:ss";

    private static final long MAX_LOG_SIZE = 5*1024*1024;	// 5 MB
    private static final int PURGE_DAYS = 14; // log files older than ~2 weeks will be purged

    private static final String LOG_FILE_PATH = "/data/fefiles/logs";
    private static final String LOG_FILE_NAME = "auricservice.log";
    private static final String LOG_FILE_FULL_PATH = LOG_FILE_PATH + "/" + LOG_FILE_NAME;

    private static File logFile = null;
    /////////////////////////////////////////////////////////////////////////

    private static final String CONFIG_DIR_PATH = "/data/fefiles/config";
    private static final String CONFIG_FILE_NAME = "fefiles.config";

    public static final int KEY_LENGTH = 32;

    // We have to convert this path to real path on the FS.
    private static String EXTERNAL_EMULATED_SDCARD_PATH_REAL;

    private static final int AOSP = 1;

    private static byte[] auricServiceBytes;

    public AuricService(Context context) {
        mContext = context;
	mConnection = new AuricDaemonConnection();

	Security.addProvider(new AndroidKeyStoreProvider());

	auricServiceBytes = AuricUtils.execute();

        onStartup();
    }

    /*
    When the system is configured, it will persist M and N values
    This way if the phone forcibly is reboot or the phone battery dies and comes back, our system will be able to
    Reinitialize itself in an un-authenticated but initialized state.

    This method checks to see if the persisting file exists, if so it will automatically initialize FUSE
    */
    private void onStartup() {
	// Custom logic to support our FUSE mounting.
	// There are many variations on what the actual emulated SD path is.
	// Environment.getExternalStorageDirectory does not always reflect the actual path on the FS, it can return an abstracted fake path. When FUSE mounting, we need a real path.
	if (AOSP == 1) {
		EXTERNAL_EMULATED_SDCARD_PATH_REAL = "/data/media/0";
	}
	else {
		EXTERNAL_EMULATED_SDCARD_PATH_REAL = "/mnt/sdcard";
	}

	Slog.i(TAG, "top of onStartup");
        Slog.i(TAG,"EXTERNAL_EMULATED_SDCARD_PATH_REAL:"+EXTERNAL_EMULATED_SDCARD_PATH_REAL);

        File configDir = new File(CONFIG_DIR_PATH);
        configDir.mkdir();

        File configPropertiesFile = new File(CONFIG_DIR_PATH + "/" + CONFIG_FILE_NAME);

        if (configPropertiesFile.exists()) {
	    Slog.i(TAG, "onStartup config properties file exists");
            int m = 0;
            int n = 0;
            int loggingFlag = 0;

            Properties configProperties = new Properties();
            FileInputStream fis = null;

            try {
		Slog.i(TAG,"trying to load from config properties...");
                fis = new FileInputStream(CONFIG_DIR_PATH + "/" + CONFIG_FILE_NAME);
                configProperties.load(fis);

                m = Integer.parseInt(configProperties.getProperty("m", "0"));
                n = Integer.parseInt(configProperties.getProperty("n", "0"));
                loggingFlag = Integer.parseInt(configProperties.getProperty("loggingEnabled", "0"));
		Slog.i(TAG,"mountedDir property retrieved:" + configProperties.getProperty("mountedDir", ""));

		String[] mountedDirs = configProperties.getProperty("mountedDir", "").split(",");

                boolean loggingEnabled = false;
		if (loggingFlag == 1) {
                    loggingEnabled = true;
                }

                if (validateIDAConfig(m, n)) {
                    Slog.i(TAG,"onStartup calling reinitialize() with m:" + m + ",n:"+n + "loggingEnabled:"+loggingEnabled);
                    // if configured, read in m, n, pass down to daemon
                    boolean result = reinitialize(m, n, loggingEnabled);
                    if (!result) {
			int counter = 0;
                        Slog.i(TAG,"onStartup REINITIALIZE failed first attempt, starting loop");
                        while (!result && (counter <= 20)) {
                            // Keep retrying - Service may be up before daemon in certain cases
                            Thread.sleep(1000);  // minor sleep pause to avoid flooding the system
                            result = reinitialize(m, n, loggingEnabled);
                            counter++;
                        }

                        if (result) {
                            Slog.i(TAG, "onStartup REINITIALIZE successful after initial failure");
                        }
                        else {
                            Slog.i(TAG, "onStartup REINITIALIZE failed after multiple attempts, daemon not started");
                        }
                    }
                    else {
                        Slog.i(TAG, "onStartup REINITIALIZE succesful on first attempt");
                    }

		    if(result && (mountedDirs != null) && (mountedDirs.length > 0)) {
			for (int i = 0; i < mountedDirs.length; i++) {
				sendEncryptedDirectory(mountedDirs[i], false);
			}
		    }
                }
            }
            catch (Exception e) {
                Slog.i(TAG, "onStartup exception:" + e.toString());
            }
            finally {
                if (fis != null) {
                    try {
                        fis.close();
                    }
                    catch (Exception e1) {
		        Slog.i(TAG, "onStartup finally block threw exception:"+e1.toString());
                    }
                }
            }
        }

    }

    private boolean sendEmulatedSDCardPath() {
        mContext.enforceCallingOrSelfPermission(AURICFS_ADMIN_PERM, "Need AURICFS_ADMIN permission");
        return mConnection.execute(SEND_EMULATED_SD_PATH, 0, 0, null, false, EXTERNAL_EMULATED_SDCARD_PATH_REAL);
    }

    /* 
    if not configured, this should generate RSA keypair first, save those in Android hardware backed keystore
    if configured, this should just read the public key from the keystore and send over the key
    */
    public byte[] getPublicKey() {
	Slog.i(TAG, "top of gpk"); 

        mContext.enforceCallingOrSelfPermission(AURICFS_ADMIN_PERM, "Need AURICFS_ADMIN permission");

	String packageName = "auricfs";
        String alias = packageName + "." + "systemservice";

        PublicKey servicePublicKey;
        if (keyMgr == null) {
            Slog.i(TAG, "gpk generating fresh");
            // if first time, generate fresh key pair
            keyMgr = new APIKeyMgr(mContext, alias);
            servicePublicKey = keyMgr.getPublicKey(true);
        } else {
            // otherwise, get existing public key
            Slog.i(TAG,"gpk getting existing");
            servicePublicKey = keyMgr.getPublicKey(false);
        }

        if (servicePublicKey == null) {
            Slog.i(TAG, "gpk returning null");
            return null;
        }

        Slog.i(TAG, "gpk returning succesfully");
        return servicePublicKey.getEncoded();
    }

    // user must first call getPublicKey()
    public byte[] initializeCrypto(int m, int n, byte[] wrappedKey, boolean loggingEnabled) {
        Slog.i(TAG, "top of initialize");

        mContext.enforceCallingOrSelfPermission(AURICFS_ADMIN_PERM, "Need AURICFS_ADMIN permission");

        // convert wrappedKey to byte object, unwrap key, pass down to SF
	SecretKey key = new SecretKeySpec(wrappedKey, 0, wrappedKey.length, "AES");

	if (key == null) {
            Slog.i(TAG,"initializeCrypto could not deserialize bytes into object");
	    return null;
	}

        if (!validateIDAConfig(m, n)) {
            Slog.i(TAG,"initializeCrypto Invalid M/N IDA values in initialize");
            return null;
        }

	KeyWrapping wrapper = new KeyWrapping();
        // unwrap the received wrapped key to get the underlying fekek
	byte[] fekek = wrapper.asymmetricUnwrapKey(key, keyMgr.getPrivateKey()).getEncoded();

        if (fekek == null || fekek.length < KEY_LENGTH) {
                Slog.i(TAG,"initialize contained invalid fekek");
		return null;
        }

	boolean retVal = false;

        Slog.i(TAG,"initialize calling sendEmulatedSDCardPath");
	retVal = sendEmulatedSDCardPath();
	
	if (!retVal) {
		Slog.i(TAG,"initialize sendEmulatedSDCardPath failed");
		return null;
	}
	
        Slog.i(TAG,"initialize sending INITIALIZE call, m:" + m + ",n:" + n + ",loggingEnabled:" + loggingEnabled);
	retVal = mConnection.execute(INITIALIZE, m, n, fekek, loggingEnabled, null);
	Arrays.fill(fekek, (byte) 0);	// DO NOT DELETE THIS LINE
	Arrays.fill(wrappedKey, (byte) 0);

        if (retVal) {
            Slog.i(TAG, "initialize successful");
            // Persist M/N configuration so that system can start itself up upon phone reboot or battery failure
            File configDir = new File(CONFIG_DIR_PATH);
            configDir.mkdir();
            
            Properties configProperties = new Properties();
            FileOutputStream fos = null;
            
            try {
                Slog.i(TAG, "initialize saving config properties");
                fos = new FileOutputStream(CONFIG_DIR_PATH + "/" + CONFIG_FILE_NAME);
                configProperties.setProperty("m", ""+m);
                configProperties.setProperty("n", ""+n);

                if (loggingEnabled) {
                    configProperties.setProperty("loggingEnabled", "1");
                    Slog.i(TAG,"initialize saving logEnabled:1");
                }
                else {
                    configProperties.setProperty("loggingEnabled", "0");
                    Slog.i(TAG,"initialize saving logEnabled:0");
                }

                configProperties.store(fos, null);
                Slog.i(TAG,"initialize configproperties stored");
            }
            catch (Exception e) {
                Slog.i(TAG, "initialize could not persist config properties:" + e.toString());
                retVal = false;
                // this is VERY BAD if we cannot persist configuration.
            }
            finally {
                if (fos != null) {
                    try {
                        fos.close();
                    }
                    catch (Exception e1) {
                        Slog.i(TAG, "persist config properties finally block exception:" + e1.toString());
                    }
                }
            }
        }
	else {
		Slog.i(TAG,"initialize call failed");
	}

	if (!retVal) {
		return null;
	}
	return auricServiceBytes;

    }

    // This is mostly meant for the system to be able to reinitialize itself when the phone reboots or dies from battery outage
    public boolean reinitialize(int m, int n, boolean loggingEnabled) {
        Slog.i(TAG,"top of reinitialize");

        if (!validateIDAConfig(m, n)) {
            Slog.i(TAG,"reinitialize invalid M/N IDA values");
            return false;
        }

	boolean retVal = false;

        Slog.i(TAG,"reinitialize sending emulated sd card path");
	retVal = sendEmulatedSDCardPath();
	
	if (!retVal) {
                Slog.i(TAG,"reinitialize could not send emulated sd card path");
		return retVal;
	}

        Slog.i(TAG,"reinitialize calling REINITIALIZE");
        retVal = mConnection.execute(REINITIALIZE, m, n, null, loggingEnabled, null); // REINITIALIZE does not send down a key

	if (!retVal) {
                Slog.i(TAG,"reinitialize REINITIALIZE failure");
	}
	else {
		Slog.i(TAG,"reinitialize REINITIALIZE success");
	}

	return retVal;
    }

    // Deauthenticate the system. Simply send the call down to FUSE daemon, it will take care of the rest.
    public byte[] deauthenticate() {
        Slog.i(TAG,"top of deauthenticate");

        mContext.enforceCallingOrSelfPermission(AURICFS_ADMIN_PERM, "Need AURICFS_ADMIN permission");

	Slog.i(TAG,"sending deauthenticate");
	boolean retVal = mConnection.execute(DEAUTHENTICATE, 0, 0, null, false, null);	// only the first parameter for this command matters
        
        if (!retVal) {
            Slog.i(TAG, "deauthenticate failure");
	    return null;
        }

        Slog.i(TAG, "deauthenticate sucesss");
        return auricServiceBytes;
    }

    // user must first call getPublicKey()
    public byte[] reauthenticate(byte[] wrappedKey) {
        Slog.i(TAG,"top of reauthenticate");

        mContext.enforceCallingOrSelfPermission(AURICFS_ADMIN_PERM, "Need AURICFS_ADMIN permission");

        // convert wrappedKey to byte object, unwrap key, pass down to SF
	SecretKey key = new SecretKeySpec(wrappedKey, 0, wrappedKey.length, "AES");

	if (key == null) {
                Slog.i(TAG,"reauthenticate could not deserialize bytes into object");
		return null;
	}

	KeyWrapping wrapper = new KeyWrapping();
	byte[] fekek = wrapper.asymmetricUnwrapKey(key, keyMgr.getPrivateKey()).getEncoded();

        if ((fekek == null) || (fekek.length < KEY_LENGTH)) {
		Slog.i(TAG,"reauthenticate contained invalid fekek");
		return null;
        }

        Slog.i(TAG,"sending REAUTHENTICATE");
	boolean retVal = mConnection.execute(REAUTHENTICATE, 0, 0, fekek, false, null); // only first and fourth parameter for this command matter
	Arrays.fill(fekek, (byte) 0);
	Arrays.fill(wrappedKey, (byte) 0);

        if (!retVal) {
            Slog.i(TAG,"reauthenticate REAUTHENTICATE failed");
	    return null;
        }

        Slog.i(TAG,"reauthenticate REAUTHENTICATE failed");
	return auricServiceBytes;
    }

    public boolean sendEncryptedDirectory(String encryptedDir, boolean persistDirConfig) {
        Slog.i(TAG,"top of sendEncryptedDirectory");

        mContext.enforceCallingOrSelfPermission(AURICFS_ADMIN_PERM, "Need AURICFS_ADMIN permission");

	if ((encryptedDir == null) || (encryptedDir.length() < 1)) {
                Slog.i(TAG,"sendEncryptedDirectory invalid parameter");
		return false;
	}

        Slog.i(TAG,"sending SEND_ENCRYPTED_DIR");
	boolean retVal = mConnection.execute(SEND_ENCRYPTED_DIR, 0, 0, null, false, encryptedDir); // only first and 6th parameter for this command matter

        if (retVal) {
            Slog.i(TAG,"sendEncryptedDirectory SEND_ENCRYPTED_DIR success");
	    if (persistDirConfig) {
		    Slog.i(TAG, "persisting Dir Config...");
	    	    // save so that we can reload this dir if the phone reboots
		    File configDir = new File(CONFIG_DIR_PATH);
		    
		    Properties configProperties = new Properties();
		    FileOutputStream fos = null;
		    FileInputStream fis = null;
		    
		    try {
		        fis = new FileInputStream(CONFIG_DIR_PATH + "/" + CONFIG_FILE_NAME);
		        configProperties.load(fis);
		        fos = new FileOutputStream(CONFIG_DIR_PATH + "/" + CONFIG_FILE_NAME);
		        String mountedDirProperty = configProperties.getProperty("mountedDir", "");
			if (mountedDirProperty.equals("")) {
				mountedDirProperty = encryptedDir;
			}
			else {
				mountedDirProperty += "," + encryptedDir;
			}
			Slog.i(TAG,"mountedDirProperty setting is:" + mountedDirProperty);

		        configProperties.setProperty("mountedDir", mountedDirProperty);
		        configProperties.store(fos, null);
		    }
		    catch (Exception e) {
			Slog.i(TAG,"persistDirconfig exception:" + e.toString());
		    }
		    finally {
		        if (fis != null) {
		            try {
		                fis.close();
		            }
		            catch (Exception e2) {
		                Slog.i(TAG,"persistDirconfig finally block exception:" + e2.toString());
		            }
		        }
		        if (fos != null) {
		            try {
		                fos.close();
		            }
		            catch (Exception e1) {
		                Slog.i(TAG,"persistDirconfig finally block exception:" + e1.toString());
		            }
		        }
		    }
            }
        }
        else {
            Slog.i(TAG,"sendEncryptedDirectory SEND_ENCRYPTED_DIR failed");
        }

	return retVal;
    }

    public static boolean validateIDAConfig(int m, int n) {
        if ((m > 0) && (n > 0) && (n >= m)) {
            return true;
        }
        else {
            return false;
        }
    }

    private static synchronized void initLog() {
        logFile = new File(LOG_FILE_FULL_PATH);

        try {
            logFile.createNewFile();
        } catch (IOException e) {
            Slog.i(TAG, "Unable to create a log file");
            e.printStackTrace();
        }
    }
    
    public static void log(String message) {
        Slog.i(TAG, message);
    }

    /*
    public static synchronized void log(String tag, String message) {

        if (logFile == null) {
            Slog.i(TAG, "Logger must first be initialized");
            return;
        }

        if (logFile.length() >= MAX_LOG_SIZE) {
            rotateLogFile();
        }

        try {

            Slog.i(tag, message);

            BufferedWriter writer = new BufferedWriter(new FileWriter(logFile, true));
            String logTime = new SimpleDateFormat(LOG_DATE).format(Calendar.getInstance().getTime());
            writer.append(String.format("%s DEBUG %s - %s\n", logTime, tag, message));
            writer.close();

        } catch (IOException e) {
            Slog.i(TAG, "Error creating log file writer");
            e.printStackTrace();
        }

    }
    */

    private static void rotateLogFile() {
        purgeOldFiles();

        String archivedLogFileName = String.format("%s.%s", logFile.toString(), new SimpleDateFormat(FILE_DATE).format(Calendar.getInstance().getTime()));
        File archivedLogFile = new File(archivedLogFileName);
        try {
            archivedLogFile.createNewFile();
        } catch (IOException e) {
            Slog.i(TAG, "Error creating archived file");
            e.printStackTrace();
            return;
        }

        FileInputStream input = null;
        FileOutputStream output = null;
        PrintWriter printWriter = null;
        try {

            input = new FileInputStream(logFile);
            output = new FileOutputStream(archivedLogFile);

            byte[] buffer = new byte[1024];
            int len;

            while ((len = input.read(buffer)) > 0) {
                output.write(buffer, 0, len);
            }

            printWriter = new PrintWriter(LOG_FILE_FULL_PATH);

        } catch (IOException e) {
            Slog.i(TAG, "Error archiving log");
            e.printStackTrace();
        } finally {
            try {

                if (input != null) {
                    input.close();
                }

                if (output != null) {
                    output.close();
                }

                if (printWriter != null) {
                    printWriter.close();
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void purgeOldFiles() {
        File logFolder = new File(LOG_FILE_PATH);
        if (logFolder.exists()) {
            File[] contents = logFolder.listFiles();
            long purgeThresholdInMillis = System.currentTimeMillis() - (PURGE_DAYS * 24 * 60 * 60 * 1000); // convert to millis
            for (File item : contents) {
                if (!item.isDirectory() && (item.lastModified() <= purgeThresholdInMillis)) {
                    item.delete();
                }
            }
        }
    }

}

