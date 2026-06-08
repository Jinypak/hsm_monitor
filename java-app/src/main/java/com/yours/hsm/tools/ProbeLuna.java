package com.yours.hsm.tools;

import com.safenetinc.luna.provider.LunaProvider;

import java.security.Provider;
import java.security.Security;
import java.util.TreeSet;

/** LunaProvider 가 노출하는 Cipher 서비스(특히 wrap 계열) 이름을 덤프한다. */
public final class ProbeLuna {
    public static void main(String[] args) {
        Provider luna = Security.getProvider("LunaProvider");
        if (luna == null) { luna = new LunaProvider(); Security.addProvider(luna); }
        System.out.println("LunaProvider version=" + luna.getVersionStr());

        TreeSet<String> ciphers = new TreeSet<>();
        TreeSet<String> wrapLike = new TreeSet<>();
        for (Provider.Service s : luna.getServices()) {
            if ("Cipher".equals(s.getType())) {
                ciphers.add(s.getAlgorithm());
                String low = s.getAlgorithm().toLowerCase();
                if (low.contains("wrap") || low.contains("kw") || low.contains("aes")) {
                    wrapLike.add(s.getAlgorithm());
                }
            }
        }
        System.out.println("=== Cipher (wrap/kw/aes 계열) ===");
        wrapLike.forEach(c -> System.out.println("   " + c));
        System.out.println("=== 전체 Cipher 수: " + ciphers.size() + " ===");
        ciphers.forEach(c -> System.out.println("   " + c));
    }
}
