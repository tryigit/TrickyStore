package android.system.keystore2;

import android.hardware.security.keymint.KeyParameter;
import android.os.IBinder;
import android.os.IInterface;

import androidx.annotation.Nullable;

public interface IKeystoreSecurityLevel extends IInterface {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreSecurityLevel";

    CreateOperationResponse createOperation(KeyDescriptor key, KeyParameter[] operationParameters, boolean forced);

    KeyMetadata generateKey(KeyDescriptor key, @Nullable KeyDescriptor attestationKey,
                            KeyParameter[] params, int flags, byte[] entropy);

    class Stub {
        public static final int TRANSACTION_createOperation = 1;
        public static final int TRANSACTION_generateKey = 2;

        public static IKeystoreSecurityLevel asInterface(IBinder b) {
            throw new RuntimeException("");
        }
    }
}
