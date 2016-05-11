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

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.util.Slog;
import libcore.io.IoUtils;
import libcore.io.Streams;

import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.util.Arrays;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

////////////////// Daemon communication protocol //////////////////
/*
First 2 bytes make up a short for the length of the message.

The message itself will be
XXYYzz...

Where XX is the first 2 bytes that dictate the message length (serialized short)
YY is the next 2 bytes that dictate the message type (serialized short)
And then zzzzz... would be anything leftever that particular message needs to send.

From System Service to Daemon
10 - Initialize Lib with M,N,Key. First time initialization. Should change passthrough to 0 on success.
11 - Lock system. Set workgroup key to filler, change authenticated flag to 0.
12 - Reauthenticate system. Set workgroup key to real key, change authenticated flag to 1.
13 - Re-initialize lib with M, N, and fake key upon rebooting. pass set to 0, authenticated set to 0.
14 - Send down from Java to C daemon the external emulated SD card path.
15 - Send encrypted directory. Daemon will copy it into the FUSE mount and symbolically link the original to the same folder within the FUSE mount

From Daemon to System Service - Just reponses.

100 - Success
101 - Failure

*/
public class AuricDaemonConnection {
    private static final String TAG = "AuricDaemonConnection";

    private InputStream mIn;
    private OutputStream mOut;
    private LocalSocket mSocket;

    private static final int MAX_LENGTH = 1024;
    private final byte buf[] = new byte[MAX_LENGTH];

    public AuricDaemonConnection() {
	
    }

    private static final String SOCKET_NAME = "auricfsd"; // This is the name of our Android system socket

    public synchronized boolean transact(short cmd, int m, int n, byte[] fekek, boolean loggingEnabled, String stringToSend) {
	Slog.e(TAG, "top of transact");
        if (!connect()) {
            Slog.e(TAG, "connection failed");
            return false;
        }

        if (!writeCommand(cmd, m, n, fekek, loggingEnabled, stringToSend)) {
            /*
             * If the daemon died and restarted in the background (unlikely but
             * possible) we'll fail on the next write (this one). Try to
             * reconnect and write the command one more time before giving up.
             */
            Slog.e(TAG, "write command failed? reconnect!");
            if (!connect() || !writeCommand(cmd, m, n, fekek, loggingEnabled, stringToSend)) {
                return false;
            }
        }

        Slog.i(TAG, "sent: '" + cmd + "'");

        final int replyLength = readReply();
        if (replyLength > 0) {
	    
            final int result = (((int) buf[0]) & 0xff) | ((((int) buf[1]) & 0xff) << 8);
	
		if (result == AuricService.SUCCESS_RESPONSE) {
			Slog.i(TAG, "received success response");
			return true;
		}
		else if (result == AuricService.FAILURE_RESPONSE) {
			Slog.i(TAG, "received failure response");
			return false;
		}
		else {
			Slog.i(TAG, "received unknown response");
			return false;
		}
	

        } else {
            Slog.i(TAG, "transact fail");
            return false;
        }
    }

    public boolean execute(short cmd, int m, int n, byte[] fekek, boolean loggingEnabled, String stringToSend) {
        Slog.i(TAG, "executing " + cmd);
        return transact(cmd, m, n, fekek, loggingEnabled, stringToSend);
    }

    public boolean connect() {
Slog.e(TAG, "top of connect");
        if (mSocket != null) {
	Slog.e(TAG, "top of connect return true premature");
            return true;
        }
        try {
    	    mSocket = new LocalSocket();

	    Slog.i(TAG, "getting LocalSocketAddress of reserved socket");
	    LocalSocketAddress address = new LocalSocketAddress(SOCKET_NAME, LocalSocketAddress.Namespace.RESERVED);

	    if (address != null) {
		Slog.i(TAG, "not null");
	    }
		
            mSocket.connect(address);

            mIn = mSocket.getInputStream();
            mOut = mSocket.getOutputStream();
        } catch (IOException ex) {
	    Slog.i(TAG, ex.toString());
            disconnect();
            return false;
        }
        return true;
    } 

    public void disconnect() {
        Slog.i(TAG, "disconnecting...");
        IoUtils.closeQuietly(mSocket);
        IoUtils.closeQuietly(mIn);
        IoUtils.closeQuietly(mOut);

        mSocket = null;
        mIn = null;
        mOut = null;
    }

    private boolean readFully(byte[] buffer, int len) {
        try {
            Streams.readFully(mIn, buffer, 0, len);
        } catch (IOException ioe) {
            Slog.e(TAG, "read exception");
            disconnect();
            return false;
        }

        return true;
    }

    private int readReply() {
        if (!readFully(buf, 2)) {
            return -1;
        }

        final int len = (((int) buf[0]) & 0xff) | ((((int) buf[1]) & 0xff) << 8);
        if ((len < 1) || (len > buf.length)) {
            Slog.e(TAG, "invalid reply length (" + len + ")");
            disconnect();
            return -1;
        }

        if (!readFully(buf, len)) {
            return -1;
        }

        return len;
    }

    /*
    This method will act according to the passed in command cmd, and eventually write a message into the socket stream.
    The daemon will be on the other side of that socket stream, listening.
    See top of this file for the various cmd definitions.
    */
    private boolean writeCommand(short cmd, int m, int n, byte[] fekek, boolean loggingEnabled, String stringToSend) {
	Slog.e(TAG, "top of writeCommand");

	int messageLength = 0;
        byte[] lengthBuffer = new byte[2]; // size of short
        ByteBuffer commandBB;

	if (cmd == AuricService.INITIALIZE) {
		if (!AuricService.validateIDAConfig(m, n)) {
		    Slog.e(TAG, "invalid IDA (M, N) parameters in writeCommand 10");
		    disconnect();
		    return false;
		}

		if (fekek == null || fekek.length < AuricService.KEY_LENGTH) {
		    Slog.e(TAG, "invalid key passed in during initialization");
		    disconnect();
		    return false;
		}

		messageLength = 2+2+2+2+AuricService.KEY_LENGTH; // size of 4 shorts (cmd, m, n, loggingEnabled) and then length of the fekek
		commandBB = fillInitializeCommand(messageLength, cmd, m, n, fekek, loggingEnabled);
	}
	else if (cmd == AuricService.DEAUTHENTICATE) {
		messageLength = 2; // size of 1 short (the cmd)
		commandBB = fillDeauthenticationCommand(messageLength, cmd);
	}
	else if (cmd == AuricService.REAUTHENTICATE) {
		if (fekek == null || fekek.length < AuricService.KEY_LENGTH) {
		    Slog.e(TAG, "invalid key passed in during reauthentication");
		    disconnect();
		    return false;
		}

		messageLength = 2+AuricService.KEY_LENGTH; // size of 1 short (the cmd) and then length of fekek
		commandBB = fillReauthenticationCommand(messageLength, cmd, fekek);
	}
	else if (cmd == AuricService.REINITIALIZE) {
		if (!AuricService.validateIDAConfig(m, n)) {
		    Slog.e(TAG, "invalid IDA (M, N) parameters in writeCommand reinitialize");
		    disconnect();
		    return false;
		}

		messageLength = 2+2+2+2; // size of 4 shorts (cmd, m, n, loggingEnabled)
		commandBB = fillReinitializeCommand(messageLength, cmd, m, n, loggingEnabled);
	}
	else if (cmd == AuricService.SEND_EMULATED_SD_PATH) {
		if ((stringToSend == null) || (stringToSend.equals(""))) {
		    Slog.e(TAG, "invalid parameter in SEND_EMULATED_SD_PATH command");
		    disconnect();
		    return false;
		}
		messageLength = 2 + stringToSend.getBytes().length;	// size of 1 short (the cmd) then length of serialized string
		commandBB = fillSendEmulatedSDPathCommand(messageLength, cmd, stringToSend);
	}
	else if (cmd == AuricService.SEND_ENCRYPTED_DIR) {
		if ((stringToSend == null) || (stringToSend.equals(""))) {
		    Slog.e(TAG, "invalid parameter in SEND_ENCRYPTED_DIR command");
		    disconnect();
		    return false;
		}
		messageLength = 2 + stringToSend.getBytes().length;	// size of 1 short (the cmd) then length of serialized string
		commandBB = fillSendEncryptedDirCommand(messageLength, cmd, stringToSend);
	}
	else {
	    Slog.e(TAG, "sending invalid message...");
            disconnect();
            return false;
	}

        lengthBuffer[0] = (byte) (messageLength & 0xff);
        lengthBuffer[1] = (byte) ((messageLength >> 8) & 0xff);
	
        byte[] rawBytes = new byte[commandBB.capacity()];
        try {
            commandBB.flip();
            commandBB.get(rawBytes);
            
            mOut.write(lengthBuffer, 0, 2);	// first send message length
            mOut.write(rawBytes, 0, commandBB.capacity()); // then send actuall command
        }
        catch (Exception ex) {
            Slog.e(TAG, "write error");
	    Slog.i(TAG, ex.toString());
            disconnect();
            return false;
        }
        finally {
	    Arrays.fill(rawBytes, (byte) 0);
	    Arrays.fill(lengthBuffer, (byte) 0);
	}

        return true;
    }

    private ByteBuffer fillInitializeCommand(int messageLength, short cmd, int m, int n, byte[] fekek, boolean loggingEnabled) {
        ByteBuffer commandBB = ByteBuffer.allocate(messageLength);
        commandBB.order(ByteOrder.LITTLE_ENDIAN);

	commandBB.putShort((short) cmd);
	commandBB.putShort((short) m);
	commandBB.putShort((short) n);

	if (loggingEnabled) {
		commandBB.putShort((short) 1);
	}
	else {
		commandBB.putShort((short) 0);
	}
	
        // Just copy in the fekek manually so it doesnt get unknowingly copied in
	for (int i = 0; i < AuricService.KEY_LENGTH; i++) {
		commandBB.put(fekek[i]);
	}

	return commandBB;
    }

    private ByteBuffer fillDeauthenticationCommand(int messageLength, short cmd) {
        ByteBuffer commandBB = ByteBuffer.allocate(messageLength);
        commandBB.order(ByteOrder.LITTLE_ENDIAN);

	commandBB.putShort((short) cmd);

	return commandBB;
    }

    private ByteBuffer fillReauthenticationCommand(int messageLength, short cmd, byte[] fekek) {
        ByteBuffer commandBB = ByteBuffer.allocate(messageLength);
        commandBB.order(ByteOrder.LITTLE_ENDIAN);

	commandBB.putShort((short) cmd);

        // Just copy in the fekek manually so it doesnt get unknowingly copied in
	for (int i = 0; i < AuricService.KEY_LENGTH; i++) {
		commandBB.put(fekek[i]);
	}

	return commandBB;
    }

    private ByteBuffer fillReinitializeCommand(int messageLength, short cmd, int m, int n, boolean loggingEnabled) {
        ByteBuffer commandBB = ByteBuffer.allocate(messageLength);
        commandBB.order(ByteOrder.LITTLE_ENDIAN);

	commandBB.putShort((short) cmd);
	commandBB.putShort((short) m);
	commandBB.putShort((short) n);

	if (loggingEnabled) {
		commandBB.putShort((short) 1);
	}
	else {
		commandBB.putShort((short) 0);
	}

	return commandBB;
    }

    private ByteBuffer fillSendEmulatedSDPathCommand(int messageLength, short cmd, String emulatedSDPath) {
        ByteBuffer commandBB = ByteBuffer.allocate(messageLength);
        commandBB.order(ByteOrder.LITTLE_ENDIAN);

	commandBB.putShort((short) cmd);
        commandBB.put(emulatedSDPath.getBytes());

	return commandBB;
    }

    private ByteBuffer fillSendEncryptedDirCommand(int messageLength, short cmd, String encryptedDir) {
        ByteBuffer commandBB = ByteBuffer.allocate(messageLength);
        commandBB.order(ByteOrder.LITTLE_ENDIAN);

	commandBB.putShort((short) cmd);
        commandBB.put(encryptedDir.getBytes());

	return commandBB;
    }

}
    
