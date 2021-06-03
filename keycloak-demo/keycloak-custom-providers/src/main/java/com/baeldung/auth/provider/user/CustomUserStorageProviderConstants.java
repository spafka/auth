package com.baeldung.auth.provider.user;

public final class CustomUserStorageProviderConstants {
    public static final String CONFIG_KEY_JDBC_DRIVER = "com.mysql.cj.jdbc.Driver";
    public static final String CONFIG_KEY_JDBC_URL = "jdbc:mysql://localhost:3306/myuser?createDatabaseIfNotExist=true&autoReconnect=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
    public static final String CONFIG_KEY_DB_USERNAME = "root";
    public static final String CONFIG_KEY_DB_PASSWORD = "root";
    public static final String CONFIG_KEY_VALIDATION_QUERY = "select 1";
}
