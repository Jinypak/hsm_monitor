package com.yours.hsm.tools;

import com.safenetinc.luna.provider.LunaProvider;
import com.yours.hsm.algo.AlgoCatalog;
import com.yours.hsm.algo.AlgoSpec;
import com.yours.hsm.core.ProviderProbe;

import java.security.Provider;
import java.security.Security;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 카탈로그({@link AlgoCatalog}) × LunaProvider 실제 가용성({@link ProviderProbe})을 매칭해
 * "이 HSM 에서 구현 가능한 알고리즘" 목록을 출력한다. (HSM 로그인 불필요 — 서비스 메타만 조회)
 * <p>
 * 실행: {@code ./gradlew algoList}
 */
public final class AlgoSupportProbe {

    public static void main(String[] args) {
        Provider luna = Security.getProvider("LunaProvider");
        if (luna == null) { luna = new LunaProvider(); Security.addProvider(luna); }
        System.out.println("LunaProvider version=" + luna.getVersionStr());

        ProviderProbe probe = ProviderProbe.of(luna);

        // -- Catalog algorithm availability table (grouped by family) --
        System.out.println("\n=== Catalog algorithm availability ===");
        Map<AlgoSpec.Family, List<AlgoSpec>> byFamily = AlgoCatalog.all().stream()
            .collect(Collectors.groupingBy(AlgoSpec::family, LinkedHashMap::new, Collectors.toList()));

        int ok = 0, total = 0;
        for (var entry : byFamily.entrySet()) {
            System.out.println("-- " + entry.getKey());
            for (AlgoSpec s : entry.getValue()) {
                total++;
                boolean sup = probe.supports(s);
                if (sup) ok++;
                System.out.printf("   [%s] %-22s %-12s %s%n",
                    sup ? "OK" : "  ", s.id(), s.op(), s.jceName());
            }
        }
        System.out.printf("%n-> %d of %d catalog mechanisms available%n", ok, total);

        // -- Diagnostic: PQC/ML services the provider actually exposes (to verify catalog jceName) --
        System.out.println("\n=== LunaProvider exposed services -- PQC/ML family ===");
        luna.getServices().stream()
            .filter(svc -> {
                String a = svc.getAlgorithm().toUpperCase();
                return a.contains("ML-DSA") || a.contains("MLDSA")
                    || a.contains("ML-KEM") || a.contains("MLKEM")
                    || a.contains("SLH") || a.contains("DILITHIUM") || a.contains("KYBER");
            })
            .map(svc -> svc.getType() + "." + svc.getAlgorithm())
            .sorted().distinct()
            .forEach(s -> System.out.println("   " + s));
    }
}
