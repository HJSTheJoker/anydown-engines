/* AnyDown headless integration. GPL-3.0. */
package com.tonikelope.megabasterd.headless;

import com.fasterxml.jackson.databind.JsonNode;
import com.tonikelope.megabasterd.MegaAPI;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import static com.tonikelope.megabasterd.headless.EngineMain.*;

/** Authenticated encrypted sessions; passwords and session keys never enter snapshots. */
public final class AccountVault implements AutoCloseable {
    private static final int ITERATIONS = 310000;
    private static final int LIMIT = 16 * 1024 * 1024;
    private final Path file;
    private byte[] key, salt;
    private final LinkedHashMap<String,Record> records = new LinkedHashMap<>();
    private final LinkedHashMap<String,Pending> pending = new LinkedHashMap<>();
    private final LoginProvider provider;
    interface LoginProvider {
        boolean requires2fa(String email) throws Exception;
        MegaAPI login(String email, String password, String pin) throws Exception;
    }
    static final class Record {
        String id,email,type="mega",password,user,apikey; MegaAPI api;
        Record(String id,String email,MegaAPI api) { this.id=id;this.email=email;this.api=api; }
    }
    static final class Pending {
        final String id=UUID.randomUUID().toString(),email,kind;
        final char[] password;
        final long expires=System.currentTimeMillis()+300000;
        Pending(String email,String password,String kind) { this.email=email;this.password=password.toCharArray();this.kind=kind; }
        void clear() { Arrays.fill(password,'\0'); }
    }
    public AccountVault(Path profile) throws Exception {
        this(profile,new LoginProvider() {
            public boolean requires2fa(String email) throws Exception { return new MegaAPI().check2FA(email); }
            public MegaAPI login(String email,String password,String pin) throws Exception {
                MegaAPI api=new MegaAPI(); api.login(email,password,pin);
                if(api.getSid()==null) throw new RpcException(-32010,"MEGA login failed");
                return api;
            }
        });
    }
    AccountVault(Path profile,LoginProvider provider) throws Exception {
        Files.createDirectories(profile); this.file=profile.resolve("accounts.vault");this.provider=provider;
    }
    public synchronized boolean isLocked() { return key==null; }
    public synchronized List<Map<String,Object>> list() {
        List<Map<String,Object>> out=new ArrayList<>();
        for(Record record:records.values()) out.add(map("id",record.id,"email",record.email,"authenticated",record.api!=null || record.type.equals("elc"),"locked",false,"type",record.type));
        return out;
    }
    public synchronized List<Map<String,Object>> challenges() {
        expire(); List<Map<String,Object>> out=new ArrayList<>();
        for(Pending p:pending.values()) out.add(challenge(p));
        return out;
    }
    public synchronized MegaAPI api(String accountId) throws Exception {
        requireUnlocked(); Record record=records.get(accountId);
        if(record==null || !record.type.equals("mega")) throw new RpcException(-32602,"Unknown MEGA account");
        if(record.api==null) {
            if(record.password==null)throw new RpcException(-32010,"Reconnect this imported account before use");
            Object result=call("account.login",JSON.valueToTree(map("email",record.email,"password",record.password)));
            if(JSON.valueToTree(result).has("challenge"))throw new RpcException(-32010,"Complete the account authentication challenge, then retry");
        }
        return records.get(accountId).api;
    }
    public synchronized Object call(String method,JsonNode params) throws Exception {
        expire();
        switch(method) {
            case "account.list": return map("accounts",list(),"locked",isLocked(),"configured",Files.exists(file),"challenges",challenges());
            case "account.unlock": unlock(required(params,params.has("masterPassword")?"masterPassword":"password"));return map("accounts",list(),"locked",false);
            case "account.lock": close();return map("locked",true);
            case "account.elc.add": {
                requireUnlocked();String host=required(params,"host").toLowerCase(Locale.ROOT);validateHost(host);
                String id=records.values().stream().filter(r->r.type.equals("elc") && r.email.equalsIgnoreCase(host)).map(r->r.id).findFirst().orElse(UUID.randomUUID().toString());
                Record record=new Record(id,host,null);record.type="elc";record.user=required(params,"user");record.apikey=required(params,"apikey");
                Record before=records.put(id,record);try{persist();}catch(Exception ex){if(before==null)records.remove(id);else records.put(id,before);throw ex;}
                return map("account",map("id",id,"email",host,"type","elc","authenticated",true,"locked",false));
            }
            case "account.login": {
                if(isLocked() && params.hasNonNull("masterPassword")) unlock(required(params,"masterPassword"));

                String email=required(params,"email").trim();
                // Upstream interpolates email into JSON, so reject control/quote characters.
                if(email.length()>320 || !email.matches("[^\\s\\\"\\\\@]+@[^\\s\\\"\\\\@]+")) throw new RpcException(-32602,"Invalid account email");
                String password=required(params,"password");
                String pin=params.path(params.has("pincode")?"pincode":"otp").asText("");
                if(isLocked()) {
                    if(pending.size()>=8)throw new RpcException(-32010,"Too many pending login challenges");
                    Pending p=new Pending(email,password,"masterPassword");pending.put(p.id,p);return map("challenge",challenge(p));
                }
                if(pin.isEmpty() && provider.requires2fa(email)) {
                    if(pending.size()>=8) throw new RpcException(-32010,"Too many pending login challenges");
                    Pending p=new Pending(email,password,"2fa");pending.put(p.id,p);
                    return map("challenge",challenge(p));
                }
                return login(email,password,pin.isEmpty()?null:pin);
            }
            case "challenge.respond": {
                String id=required(params,params.has("id")?"id":"challengeId");Pending p=pending.get(id);
                if(p==null) throw new RpcException(-32602,"Unknown or expired challenge");
                if(params.path("cancel").asBoolean(false)){pending.remove(id);p.clear();return map("cancelled",true);}
                String pin=required(params,params.has("value")?"value":"pincode");
                if(p.kind.equals("legacyMasterPassword")) {
                    Object result=importRecords(LegacyProfileImporter.read(Paths.get(p.email),pin));pending.remove(id);p.clear();return result;
                }
                if(p.kind.equals("masterPassword")) {
                    unlock(pin);
                    Object result=call("account.login",JSON.valueToTree(map("email",p.email,"password",new String(p.password))));
                    pending.remove(id);p.clear();return result;
                }
                requireUnlocked();
                if(!pin.matches("[0-9]{6}")) throw new RpcException(-32602,"Enter a six digit authentication code");
                Object result=login(p.email,new String(p.password),pin);pending.remove(id);p.clear();return result;
            }
            case "account.remove": {
                requireUnlocked();String id=required(params,params.has("accountId")?"accountId":"id");Record old=records.remove(id);
                try { persist(); } catch(Exception ex) { if(old!=null)records.put(id,old);throw ex; }
                return map("removed",old!=null);
            }
            case "account.export": {
                requireUnlocked();Path output=Paths.get(required(params,"path")).toAbsolutePath();
                if(output.equals(file.toAbsolutePath())) throw new RpcException(-32602,"Choose a separate export path");
                String exportPassword=required(params,"masterPassword");
                if(exportPassword.length()<8)throw new RpcException(-32602,"Use an export password of at least eight characters");
                byte[] exportSalt=random(16);byte[] exportKey=derive(exportPassword,exportSalt);
                try { writePrivate(output,envelope(serialize(),exportKey,exportSalt),false); } finally { Arrays.fill(exportKey,(byte)0); }
                return map("exported",records.size());
            }
            case "account.import": {
                requireUnlocked();Path input=Paths.get(required(params,"path"));
                if(LegacyProfileImporter.supports(input)) {
                    try { return importRecords(LegacyProfileImporter.read(input,params.path("masterPassword").asText(null))); }
                    catch(LegacyProfileImporter.PasswordRequired ex) {
                        if(pending.size()>=8)throw new RpcException(-32010,"Too many pending challenges");
                        Pending p=new Pending(input.toAbsolutePath().toString(),"","legacyMasterPassword");pending.put(p.id,p);return map("challenge",challenge(p));
                    }
                }
                return importRecords(read(input,required(params,"masterPassword")));
            }
            default: throw new RpcException(-32601,"Unknown account method");
        }
    }
    private Object login(String email,String password,String pin) throws Exception {
        MegaAPI api=provider.login(email,password,pin);
        String id=records.values().stream().filter(r->r.type.equals("mega") && r.email.equalsIgnoreCase(email)).map(r->r.id).findFirst().orElse(UUID.randomUUID().toString());
        Record previous=records.put(id,new Record(id,email,api));
        try { persist(); } catch(Exception ex) { if(previous==null)records.remove(id);else records.put(id,previous);throw ex; }
        return map("account",map("id",id,"email",email,"authenticated",true));
    }
    private void requireUnlocked() throws RpcException { if(isLocked())throw new RpcException(-32011,"Unlock the account vault first"); }
    private void unlock(String password) throws Exception {
        if(!isLocked())return;
        if(!Files.exists(file)) {
            if(password.length()<8)throw new RpcException(-32602,"Use a master password of at least eight characters");
            salt=random(16);key=derive(password,salt);
            try { persist(); } catch(Exception ex) { close();throw ex; }
            return;
        }
        LinkedHashMap<String,Record> loaded=read(file,password);
        JsonNode envelope=JSON.readTree(Files.readAllBytes(file));byte[] candidateSalt=decode(envelope,"salt",16);
        byte[] candidateKey=derive(password,candidateSalt);
        records.clear();records.putAll(loaded);salt=candidateSalt;key=candidateKey;
    }
    private LinkedHashMap<String,Record> read(Path input,String password) throws Exception {
        if(Files.size(input)>LIMIT)throw new RpcException(-32602,"Account vault exceeds size limit");
        JsonNode envelope=JSON.readTree(Files.readAllBytes(input));
        if(envelope.path("version").asInt()!=1 || envelope.path("iterations").asInt()!=ITERATIONS)throw new RpcException(-32602,"Unsupported account vault format");
        byte[] inputSalt=decode(envelope,"salt",16),iv=decode(envelope,"iv",12),derived=derive(password,inputSalt),plain;
        try {
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(derived,"AES"),new GCMParameterSpec(128,iv));cipher.updateAAD("anydown-account-vault-v1".getBytes("UTF-8"));
            plain=cipher.doFinal(Base64.getDecoder().decode(envelope.path("data").asText()));
        } catch(GeneralSecurityException | IllegalArgumentException ex) { throw new RpcException(-32011,"Incorrect master password or damaged account vault"); }
        finally { Arrays.fill(derived,(byte)0); }
        try {
            JsonNode entries=JSON.readTree(plain); if(!entries.isArray() || entries.size()>1000)throw new RpcException(-32602,"Invalid account vault");
            LinkedHashMap<String,Record> loaded=new LinkedHashMap<>();
            for(JsonNode entry:entries) {
                Record record=new Record(required(entry,"id"),required(entry,"email"),null);record.type=entry.path("type").asText("mega");
                if(!Arrays.asList("mega","elc").contains(record.type))throw new RpcException(-32602,"Invalid account type in vault");
                if(entry.hasNonNull("session")) {
                    byte[] session=Base64.getDecoder().decode(required(entry,"session"));
                    try{record.api=deserializeSession(session);}finally{Arrays.fill(session,(byte)0);}
                }
                record.password=entry.path("password").asText(null);record.user=entry.path("user").asText(null);record.apikey=entry.path("apikey").asText(null);
                loaded.put(record.id,record);
            }
            return loaded;
        } finally { Arrays.fill(plain,(byte)0); }
    }
    static MegaAPI deserializeSession(byte[] session) throws IOException,ClassNotFoundException {
        try(ObjectInputStream stream=new ObjectInputStream(new ByteArrayInputStream(session)) {
            @Override protected Class<?> resolveClass(ObjectStreamClass descriptor) throws IOException,ClassNotFoundException {
                String name=descriptor.getName();
                if(!Arrays.asList("com.tonikelope.megabasterd.MegaAPI","java.math.BigInteger","java.lang.Number","[I","[B","[Ljava.math.BigInteger;").contains(name))throw new InvalidClassException("Unsupported session class");
                return super.resolveClass(descriptor);
            }
            @Override protected Class<?> resolveProxyClass(String[] names) throws IOException {throw new InvalidClassException("Proxies not supported");}
        }) {
            stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter("maxdepth=16;maxrefs=10000;maxarray=1048576;maxbytes=16777216"));
            Object value=stream.readObject();if(!(value instanceof MegaAPI))throw new InvalidObjectException("Not a MEGA session");return (MegaAPI)value;
        }
    }
    public synchronized JsonNode elcCredentials(String host) throws Exception {
        requireUnlocked();Record record=records.values().stream().filter(r->r.type.equals("elc") && r.email.equalsIgnoreCase(host)).findFirst().orElse(null);
        if(record==null)throw new RpcException(-32010,"Add ELC credentials for this link provider in Accounts first");
        return JSON.valueToTree(map("host",record.email,"user",record.user,"apikey",record.apikey));
    }
    static void validateHost(String host) throws RpcException {
        try{java.net.URI uri=new java.net.URI("https://"+host);if(host==null || host.length()>253 || !host.equals(uri.getHost()) || uri.getPort()!=-1 || uri.getUserInfo()!=null || !uri.getPath().isEmpty())throw new Exception();}
        catch(Exception ex){throw new RpcException(-32602,"ELC host must be a hostname without a path or port");}
    }
    private Object importRecords(LinkedHashMap<String,Record> imported) throws Exception {
        requireUnlocked();LinkedHashMap<String,Record> before=new LinkedHashMap<>(records);
        for(Record record:imported.values()) {
            String id=records.values().stream().filter(r->r.type.equals(record.type) && r.email.equalsIgnoreCase(record.email)).map(r->r.id).findFirst().orElse(UUID.randomUUID().toString());
            record.id=id;records.put(id,record);
        }
        try{persist();}catch(Exception ex){records.clear();records.putAll(before);throw ex;}
        return map("imported",imported.size(),"accounts",list());
    }
    private byte[] serialize() throws Exception {
        List<Object> entries=new ArrayList<>();
        for(Record record:records.values()) {
            String session=null;
            if(record.api!=null){ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(ObjectOutputStream stream=new ObjectOutputStream(bytes)){stream.writeObject(record.api);}session=Base64.getEncoder().encodeToString(bytes.toByteArray());}
            entries.add(map("id",record.id,"email",record.email,"type",record.type,"session",session,"password",record.password,"user",record.user,"apikey",record.apikey));
        }
        return JSON.writeValueAsBytes(entries);
    }
    private byte[] envelope(byte[] plain,byte[] encryptionKey,byte[] encryptionSalt) throws Exception {
        try {
            byte[] iv=random(12);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(encryptionKey,"AES"),new GCMParameterSpec(128,iv));cipher.updateAAD("anydown-account-vault-v1".getBytes("UTF-8"));
            return JSON.writeValueAsBytes(map("version",1,"iterations",ITERATIONS,"salt",Base64.getEncoder().encodeToString(encryptionSalt),"iv",Base64.getEncoder().encodeToString(iv),"data",Base64.getEncoder().encodeToString(cipher.doFinal(plain))));
        } finally { Arrays.fill(plain,(byte)0); }
    }
    private void persist() throws Exception { writePrivate(file,envelope(serialize(),key,salt),true); }
    static void writePrivate(Path destination,byte[] data,boolean replace) throws Exception {
        Path absolute=destination.toAbsolutePath();Path parent=absolute.getParent();Files.createDirectories(parent);
        Path temporary=Files.createTempFile(parent,".anydown-",".tmp");
        try {
            try { Files.setPosixFilePermissions(temporary,PosixFilePermissions.fromString("rw-------")); } catch(UnsupportedOperationException ignored) { }
            Files.write(temporary,data);
            try(java.nio.channels.FileChannel channel=java.nio.channels.FileChannel.open(temporary,StandardOpenOption.WRITE)){channel.force(true);}
            if(replace) { Files.move(temporary,absolute,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING); }
            else { Files.createLink(absolute,temporary);Files.delete(temporary); }
        } finally { Files.deleteIfExists(temporary); }
    }
    private static String required(JsonNode params,String key) throws RpcException {
        JsonNode value=params.path(key);if(!value.isTextual() || value.asText().isEmpty())throw new RpcException(-32602,"Missing "+key);return value.asText();
    }
    private static byte[] random(int length) { byte[] bytes=new byte[length];new SecureRandom().nextBytes(bytes);return bytes; }
    private static byte[] derive(String password,byte[] salt) throws Exception {
        PBEKeySpec spec=new PBEKeySpec(password.toCharArray(),salt,ITERATIONS,256);
        try { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); } finally { spec.clearPassword(); }
    }
    private static byte[] decode(JsonNode envelope,String field,int length) throws RpcException {
        try { byte[] bytes=Base64.getDecoder().decode(envelope.path(field).asText());if(bytes.length!=length)throw new IllegalArgumentException();return bytes; }
        catch(IllegalArgumentException ex){throw new RpcException(-32602,"Invalid account vault format");}
    }
    private Map<String,Object> challenge(Pending p) {
        boolean legacy=p.kind.equals("legacyMasterPassword");
        boolean master=p.kind.equals("masterPassword") || legacy;
        return map("id",p.id,"kind",p.kind,"type",master?"masterPassword":"twoFactor","message",legacy?"Enter the master password from your standalone MegaBasterd profile.":master?(Files.exists(file)?"Unlock the account vault to connect this account.":"Create a vault password of at least eight characters to encrypt this account."):"Enter your current six digit MEGA authentication code.","fields",Collections.singletonList(map("name","value","type","password","label",master?"Vault password":"Verification code")),"accountEmail",legacy?null:p.email,"expiresAt",p.expires,"configured",Files.exists(file));
    }
    private void expire() { Iterator<Pending> iterator=pending.values().iterator();while(iterator.hasNext()){Pending p=iterator.next();if(p.expires<System.currentTimeMillis()){p.clear();iterator.remove();}} }
    @Override public synchronized void close() { for(Pending p:pending.values())p.clear();pending.clear();records.clear();if(key!=null)Arrays.fill(key,(byte)0);key=null;salt=null; }
}
