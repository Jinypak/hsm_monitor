package com.yours.hsm.ui;

import com.yours.hsm.core.LunaSession;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleObjectProperty;

/** 컨트롤러 간 LunaSession 공유용 단순 홀더. */
public final class SessionHolder {

    private final ObjectProperty<LunaSession> sessionProp = new SimpleObjectProperty<>();

    /** 토큰의 키 목록이 바뀔 때마다 증가 — 각 탭이 키 콤보를 다시 로드하는 트리거. */
    private final IntegerProperty keysVersion = new SimpleIntegerProperty(0);

    public LunaSession getSession() { return sessionProp.get(); }

    public void setSession(LunaSession s) { sessionProp.set(s); }

    public ObjectProperty<LunaSession> sessionProperty() { return sessionProp; }

    public IntegerProperty keysVersionProperty() { return keysVersion; }

    /** 키 생성/삭제/라벨변경/언래핑 후 호출 — 모든 탭의 키 목록 갱신을 유발. */
    public void notifyKeysChanged() { keysVersion.set(keysVersion.get() + 1); }
}
