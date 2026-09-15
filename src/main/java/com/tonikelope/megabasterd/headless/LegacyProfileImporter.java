/* AnyDown headless integration. GPL-3.0. */
package com.tonikelope.megabasterd.headless;

import com.tonikelope.megabasterd.CryptTools;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.sql.*;
import java.util.*;

/** Reads an explicit upstream profile through a private copy; never opens the source for SQLite writes. */
final class LegacyProfileImporter {
    static final class PasswordRequired extends Exception { PasswordRequired(){super("Standalone profile password required");} }
    static boolean supports(Path input) throws Exception {
        if(Files.isDirectory(input))return Files.isRegularFile(input.resolve("megabasterd.db"));
        if(!Files.isRegularFile(input))return false;
        byte[] header=new byte[16];try(java.io.InputStream stream=Files.newInputStream(input)){if(stream.read(header)!=16)return false;}
        return Arrays.equals(header,"SQLite format 3\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }
    static LinkedHashMap<String,AccountVault.Record> read(Path input,String password) throws Exception {
        Path source=(Files.isDirectory(input)?input.resolve("megabasterd.db"):input).toRealPath();
        if(Files.size(source)>128L*1024*1024)throw new RpcException(-32602,"Standalone account database exceeds import limit");
        Path directory=Files.createTempDirectory("anydown-legacy-import-");byte[] master=null;
        try {
            Path copy=directory.resolve("megabasterd.db");copyConsistently(source,copy);
            Class.forName("org.sqlite.JDBC");
            try(Connection connection=DriverManager.getConnection("jdbc:sqlite:"+copy.toUri()+"?mode=ro")) {
                connection.setAutoCommit(false);
                try(Statement statement=connection.createStatement();ResultSet check=statement.executeQuery("PRAGMA quick_check")){if(!check.next() || !"ok".equals(check.getString(1)))throw new RpcException(-32602,"Standalone database snapshot is inconsistent; close MegaBasterd and retry");}
                String hash=setting(connection,"master_pass_hash"),salt=setting(connection,"master_pass_salt");
                if(hash!=null && !hash.isEmpty()) {
                    if(password==null || password.isEmpty())throw new PasswordRequired();
                    if(salt==null)throw new RpcException(-32602,"Standalone profile is missing its password salt");
                    master=CryptTools.PBKDF2HMACSHA256(password,Base64.getDecoder().decode(salt),CryptTools.MASTER_PASSWORD_PBKDF2_ITERATIONS,CryptTools.MASTER_PASSWORD_PBKDF2_OUTPUT_BIT_LENGTH);
                    if(!MessageDigest.isEqual(MessageDigest.getInstance("SHA-1").digest(master),Base64.getDecoder().decode(hash)))throw new RpcException(-32011,"Incorrect standalone profile password");
                }
                LinkedHashMap<String,AccountVault.Record> records=new LinkedHashMap<>();
                try(Statement statement=connection.createStatement();ResultSet rows=statement.executeQuery("SELECT email,password FROM mega_accounts")) {
                    while(rows.next()) {
                        if(records.size()>=1000)throw new RpcException(-32602,"Standalone profile contains too many accounts");
                        String email=bounded(rows.getString("email"));if(email==null || !email.matches("[^\\s\\\"\\\\@]+@[^\\s\\\"\\\\@]+"))throw new RpcException(-32602,"Invalid standalone account email");
                        AccountVault.Record record=new AccountVault.Record(UUID.randomUUID().toString(),email,null);record.password=plain(rows.getString("password"),master);
                        try(PreparedStatement session=connection.prepareStatement("SELECT ma,crypt FROM mega_sessions WHERE email=?")) {
                            session.setString(1,email);try(ResultSet result=session.executeQuery()) {if(result.next()) {
                                byte[] bytes=result.getBytes("ma");if(bytes!=null){if(bytes.length>1024*1024)throw new RpcException(-32602,"Standalone account session exceeds size limit");
                                    if(result.getInt("crypt")!=0){if(master==null)throw new RpcException(-32602,"Encrypted standalone session has no master key");bytes=CryptTools.aes_cbc_decrypt_at_rest(bytes,master);}
                                    try{record.api=AccountVault.deserializeSession(bytes);}catch(java.io.IOException | ClassNotFoundException ex){if(record.password==null)throw new RpcException(-32602,"Standalone session needs reauthentication, but no password is available");}
                                    finally{Arrays.fill(bytes,(byte)0);}
                                }
                            }}
                        }
                        if(record.api==null && (record.password==null || record.password.isEmpty()))throw new RpcException(-32602,"Standalone account has neither a session nor login credentials");
                        records.put(record.id,record);
                    }
                }
                try(Statement statement=connection.createStatement();ResultSet rows=statement.executeQuery("SELECT host,user,apikey FROM elc_accounts")) {
                    while(rows.next()) {
                        if(records.size()>=1000)throw new RpcException(-32602,"Standalone profile contains too many accounts");
                        String host=bounded(rows.getString("host"));AccountVault.validateHost(host);
                        AccountVault.Record record=new AccountVault.Record(UUID.randomUUID().toString(),host,null);record.type="elc";record.user=plain(rows.getString("user"),master);record.apikey=plain(rows.getString("apikey"),master);
                        if(record.user==null || record.apikey==null)throw new RpcException(-32602,"Incomplete standalone ELC credentials");records.put(record.id,record);
                    }
                }
                return records;
            }
        } finally {
            if(master!=null)Arrays.fill(master,(byte)0);
            try(java.util.stream.Stream<Path> files=Files.walk(directory)){for(Path path:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}
        }
    }
    private static String setting(Connection connection,String key) throws Exception {
        try(PreparedStatement statement=connection.prepareStatement("SELECT value FROM settings WHERE key=?")){statement.setString(1,key);try(ResultSet result=statement.executeQuery()){return result.next()?bounded(result.getString(1)):null;}}
    }
    private static String bounded(String value) throws RpcException {if(value!=null && value.length()>1024*1024)throw new RpcException(-32602,"Standalone account field exceeds size limit");return value;}
    private static String plain(String value,byte[] master) throws Exception {
        value=bounded(value);if(value==null || master==null)return value;byte[] bytes=CryptTools.aes_cbc_decrypt_at_rest(Base64.getDecoder().decode(value),master);
        try{return new String(bytes,java.nio.charset.StandardCharsets.UTF_8);}finally{Arrays.fill(bytes,(byte)0);}
    }
    private static void copyConsistently(Path source,Path copy) throws Exception {
        Path wal=Paths.get(source+"-wal"),copiedWal=Paths.get(copy+"-wal");
        for(int attempt=0;attempt<3;attempt++) {
            BasicFileAttributes before=Files.readAttributes(source,BasicFileAttributes.class);BasicFileAttributes walBefore=Files.exists(wal)?Files.readAttributes(wal,BasicFileAttributes.class):null;
            if(walBefore!=null && walBefore.size()>128L*1024*1024)throw new RpcException(-32602,"Standalone database journal exceeds import limit");
            Files.copy(source,copy,StandardCopyOption.REPLACE_EXISTING);Files.deleteIfExists(copiedWal);if(walBefore!=null)Files.copy(wal,copiedWal,StandardCopyOption.REPLACE_EXISTING);
            BasicFileAttributes after=Files.readAttributes(source,BasicFileAttributes.class);BasicFileAttributes walAfter=Files.exists(wal)?Files.readAttributes(wal,BasicFileAttributes.class):null;
            if(same(before,after) && same(walBefore,walAfter))return;
        }
        throw new RpcException(-32000,"Standalone profile is changing; close MegaBasterd and retry the import");
    }
    private static boolean same(BasicFileAttributes a,BasicFileAttributes b){return a==null?b==null:b!=null && a.size()==b.size() && a.lastModifiedTime().equals(b.lastModifiedTime()) && Objects.equals(a.fileKey(),b.fileKey());}
}
