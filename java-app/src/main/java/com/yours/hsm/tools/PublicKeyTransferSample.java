package com.yours.hsm.tools;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.key.LunaKey;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyTransferSample {

    public static void main(String[] args) throws Exception {
        final String PIN      = "userpin";
        final String SRC_ALIAS = "slot0_publickey-alias";  // CKE 공개키 라벨
        final String DST_ALIAS = "slot1_publickey-alias";  // CL 저장 공개키 라벨
        final Path   PUB_FILE  = Path.of("C:/Program Files/SafeNet/LunaClient/pubkey.der");

        Provider luna = Security.getProvider("LunaProvider");

        LunaSlotManager.getInstance().setDefaultSlot(0);
        KeyStore ks0 = KeyStore.getInstance("Luna", luna);
        ks0.load(null, PIN.toCharArray());

        PublicKey pub = (PublicKey) ks0.getKey(SRC_ALIAS, null);
        byte[] derBytes = pub.getEncoded();                     

        Files.write(PUB_FILE, derBytes);

        LunaSlotManager.getInstance().setDefaultSlot(1);
        KeyStore ks1 = KeyStore.getInstance("Luna", luna);
        ks1.load(null, PIN.toCharArray());

        byte[] imported = Files.readAllBytes(PUB_FILE);
        PublicKey lunaPub = KeyFactory
            .getInstance("ML-DSA-65", luna)
            .generatePublic(new X509EncodedKeySpec(imported));  

        // CL 에 공개 키 저장
        ((LunaKey) lunaPub).MakePersistent(DST_ALIAS);
    }
}
