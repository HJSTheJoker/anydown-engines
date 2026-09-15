package com.tonikelope.megabasterd.headless;

import com.tonikelope.megabasterd.CryptTools;
import com.tonikelope.megabasterd.MegaAPI;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static com.tonikelope.megabasterd.headless.EngineMain.*;

class LegacyProfileImporterTest {
    @TempDir Path root;
    private JsonNode json(Object... pairs){return JSON.valueToTree(map(pairs));}
    private static String base64(byte[] value){return Base64.getEncoder().encodeToString(value);}
    private Connection fixture(Path profile,boolean encrypted,boolean session,boolean wal) throws Exception {
        Files.createDirectories(profile);Connection connection=DriverManager.getConnection("jdbc:sqlite:"+profile.resolve("megabasterd.db"));
        try(Statement statement=connection.createStatement()) {
            if(wal)statement.execute("PRAGMA journal_mode=WAL");
            // Exact account schema from upstream DBTools.setupSqliteTables.
            statement.execute("CREATE TABLE settings(key VARCHAR(255), value TEXT, PRIMARY KEY('key'))");
            statement.execute("CREATE TABLE mega_accounts(email TEXT, password TEXT, password_aes TEXT, user_hash TEXT, PRIMARY KEY('email'))");
            statement.execute("CREATE TABLE elc_accounts(host TEXT, user TEXT, apikey TEXT, PRIMARY KEY('host'))");
            statement.execute("CREATE TABLE mega_sessions(email TEXT, ma BLOB, crypt INT, PRIMARY KEY('email'))");
        }
        byte[] salt=new byte[16];Arrays.fill(salt,(byte)42);byte[] key=CryptTools.PBKDF2HMACSHA256("legacy-master",salt,CryptTools.MASTER_PASSWORD_PBKDF2_ITERATIONS,CryptTools.MASTER_PASSWORD_PBKDF2_OUTPUT_BIT_LENGTH);
        if(encrypted){try(PreparedStatement statement=connection.prepareStatement("INSERT INTO settings VALUES(?,?)")){statement.setString(1,"master_pass_salt");statement.setString(2,base64(salt));statement.executeUpdate();statement.setString(1,"master_pass_hash");statement.setString(2,base64(MessageDigest.getInstance("SHA-1").digest(key)));statement.executeUpdate();}}
        try(PreparedStatement statement=connection.prepareStatement("INSERT INTO mega_accounts VALUES(?,?,?,?)")) {
            statement.setString(1,"legacy@example.invalid");statement.setString(2,encrypted?base64(CryptTools.aes_cbc_encrypt_at_rest("legacy-login-secret".getBytes("UTF-8"),key)):"legacy-login-secret");statement.setString(3,"");statement.setString(4,"");statement.executeUpdate();
        }
        try(PreparedStatement statement=connection.prepareStatement("INSERT INTO elc_accounts VALUES(?,?,?)")) {
            statement.setString(1,"links.example.invalid");
            // Exercise older zero-IV upstream format as well as current prefixed records.
            statement.setString(2,encrypted?base64(CryptTools.aes_cbc_encrypt_pkcs7("legacy-user".getBytes("UTF-8"),key,CryptTools.AES_ZERO_IV)):"legacy-user");
            statement.setString(3,encrypted?base64(CryptTools.aes_cbc_encrypt_at_rest("legacy-elc-secret".getBytes("UTF-8"),key)):"legacy-elc-secret");statement.executeUpdate();
        }
        if(session) {
            MegaAPI api=new MegaAPI();java.lang.reflect.Field field=MegaAPI.class.getDeclaredField("_sid");field.setAccessible(true);field.set(api,"legacy-session-secret");
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(ObjectOutputStream stream=new ObjectOutputStream(bytes)){stream.writeObject(api);}byte[] value=bytes.toByteArray();if(encrypted)value=CryptTools.aes_cbc_encrypt_at_rest(value,key);
            try(PreparedStatement statement=connection.prepareStatement("INSERT INTO mega_sessions VALUES(?,?,?)")){statement.setString(1,"legacy@example.invalid");statement.setBytes(2,value);statement.setInt(3,encrypted?1:0);statement.executeUpdate();}
        }
        return connection;
    }
    private Map<String,String> hashes(Path profile) throws Exception {
        Map<String,String> result=new TreeMap<>();try(java.util.stream.Stream<Path> paths=Files.list(profile)){for(Path path:paths.toList())result.put(path.getFileName().toString(),base64(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))));}return result;
    }
    @Test void importsEncryptedWalProfileThroughNativeChallengeWithoutChangingSource() throws Exception {
        Path standalone=root.resolve("standalone");try(Connection source=fixture(standalone,true,true,true);AccountVault vault=new AccountVault(root.resolve("target"))) {
            Map<String,String> before=hashes(standalone);vault.call("account.unlock",json("password","target-master"));
            Object request=vault.call("account.import",json("path",standalone.toString()));JsonNode challenge=JSON.valueToTree(request).path("challenge");assertEquals("legacyMasterPassword",challenge.path("kind").asText());
            assertThrows(RpcException.class,()->vault.call("challenge.respond",json("id",challenge.path("id").asText(),"value","wrong")));
            vault.call("challenge.respond",json("id",challenge.path("id").asText(),"value","legacy-master"));assertEquals(2,vault.list().size());assertTrue(vault.challenges().isEmpty());
            String megaId=vault.list().stream().filter(item->item.get("type").equals("mega")).findFirst().orElseThrow().get("id").toString();assertEquals("legacy-session-secret",vault.api(megaId).getSid());
            assertEquals("legacy-user",vault.elcCredentials("links.example.invalid").path("user").asText());assertEquals("legacy-elc-secret",vault.elcCredentials("links.example.invalid").path("apikey").asText());
            assertFalse(JSON.writeValueAsString(vault.list()).contains("secret"));assertFalse(new String(Files.readAllBytes(root.resolve("target/accounts.vault")),"UTF-8").contains("legacy"));
            assertEquals(before,hashes(standalone));
            vault.close();vault.call("account.unlock",json("password","target-master"));assertEquals("legacy-session-secret",vault.api(megaId).getSid());assertEquals("legacy-elc-secret",vault.elcCredentials("links.example.invalid").path("apikey").asText());
        }
    }
    @Test void plaintextProfileWithoutSessionsReauthenticatesUsingNativeTwoFactor() throws Exception {
        Path profile=root.resolve("plain");try(Connection fixture=fixture(profile,false,false,false)){}
        AccountVault.LoginProvider adapter=new AccountVault.LoginProvider(){
            public boolean requires2fa(String email){return true;}
            public MegaAPI login(String email,String password,String pin) throws Exception {assertEquals("legacy-login-secret",password);assertEquals("123456",pin);return new MegaAPI();}
        };
        try(AccountVault vault=new AccountVault(root.resolve("plain-target"),adapter)) {
            vault.call("account.unlock",json("password","target-master"));vault.call("account.import",json("path",profile.resolve("megabasterd.db").toString()));
            String id=vault.list().stream().filter(item->item.get("type").equals("mega")).findFirst().orElseThrow().get("id").toString();assertThrows(RpcException.class,()->vault.api(id));
            Map<String,Object> challenge=vault.challenges().get(0);assertEquals("2fa",challenge.get("kind"));vault.call("challenge.respond",json("id",challenge.get("id"),"value","123456"));assertNotNull(vault.api(id));
            vault.call("account.elc.add",json("host","new.example.invalid","user","new-user","apikey","new-secret"));assertEquals("new-secret",vault.elcCredentials("new.example.invalid").path("apikey").asText());
            assertThrows(RpcException.class,()->vault.call("account.elc.add",json("host","https://bad/path","user","u","apikey","k")));
        }
    }
}
