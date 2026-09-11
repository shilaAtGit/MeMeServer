package com.shila.weMail;

public enum OperationType {
    HEART_BEAT("00", ""),
    UPDATE_MAPPING("01", ""),
    REGISTER_SOCKET("02", ""),
    QUERY_ID_PATHS("03", ""),
    FORWARD_MESSAGE("04", ""),
    UNKNOWN("99", "未知操作");

    private final String code;
    private final String description;

    OperationType(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public static OperationType fromCode(String code) {
        for (OperationType type : values()) {
            if (type.code.equals(code)) {
                return type;
            }
        }
        return UNKNOWN;
    }

}