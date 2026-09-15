package com.tonikelope.megabasterd.headless;

import com.fasterxml.jackson.databind.JsonNode;
import com.tonikelope.megabasterd.MegaAPI;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static com.tonikelope.megabasterd.headless.EngineMain.*;

/** Offline headless regression tests. Run using java -ea -Djava.awt.headless=true. */
public final class VaultUtilitiesTest {
    @org.junit.jupiter.api.Test public void headlessRegressions() throws Exception { main(new String[0]); }
    private static JsonNode json(Object... pairs){return JSON.valueToTree(map(pairs));}
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private interface Attempt {void run() throws Exception;}
    private static void rejects(Attempt attempt,String message) throws Exception {try{attempt.run();}catch(Exception expected){return;}throw new AssertionError(message);}
    public static void main(String[] args) throws Exception {
        check(java.awt.GraphicsEnvironment.isHeadless(),"Tests must run headless");
        Path root=Files.createTempDirectory("anydown-vault-tests-");
        try{vault(root);settings(root);utilities(root);System.out.println("VaultUtilitiesTest: all checks passed");}
        finally{try(java.util.stream.Stream<Path> paths=Files.walk(root)){paths.sorted(Comparator.reverseOrder()).forEach(p->{try{Files.deleteIfExists(p);}catch(Exception ex){throw new RuntimeException(ex);}});}}
    }
    private static void vault(Path root) throws Exception {
        AtomicBoolean twoFactor=new AtomicBoolean(true);
        AccountVault.LoginProvider provider=new AccountVault.LoginProvider(){
            public boolean requires2fa(String email){return twoFactor.get();}
            public MegaAPI login(String email,String password,String pin) throws Exception {
                check(password.equals("synthetic-password"),"Password reached login adapter");
                if(twoFactor.get() && !"123456".equals(pin))throw new RpcException(-32010,"Invalid test pin");
                MegaAPI api=new MegaAPI();java.lang.reflect.Field sid=MegaAPI.class.getDeclaredField("_sid");sid.setAccessible(true);sid.set(api,"synthetic-session-secret");return api;
            }
        };
        Path profile=root.resolve("profile");AccountVault vault=new AccountVault(profile,provider);
        rejects(()->vault.call("account.unlock",json("masterPassword","short")),"Reject weak vault creation password");
        Object masterPrompt=vault.call("account.login",json("email","test@example.invalid","password","synthetic-password"));
        check(JSON.valueToTree(masterPrompt).path("challenge").path("kind").asText().equals("masterPassword"),"Missing vault password generates native challenge");
        String masterId=JSON.valueToTree(masterPrompt).path("challenge").path("id").asText();
        Object prompt=vault.call("challenge.respond",json("id",masterId,"value","synthetic-master-password"));
        String id=JSON.valueToTree(prompt).path("challenge").path("id").asText();
        check(!id.isEmpty(),"Two factor challenge is returned");
        rejects(()->vault.call("challenge.respond",json("id",id,"value","abcdef")),"Validate two-factor code");
        vault.call("challenge.respond",json("id",id,"value","123456"));
        check(vault.challenges().isEmpty(),"Resolved challenge removed");
        check(vault.list().size()==1,"Account stored");String accountId=(String)vault.list().get(0).get("id");
        check(vault.api(accountId).getSid().equals("synthetic-session-secret"),"Session retained");
        String disk=new String(Files.readAllBytes(profile.resolve("accounts.vault")),"UTF-8");
        check(!disk.contains("synthetic-") && !disk.contains("example.invalid"),"No account secrets on disk");
        check(!JSON.writeValueAsString(vault.list()).contains("synthetic-session-secret"),"Snapshot excludes session secret");
        Path exported=root.resolve("export.vault");vault.call("account.export",json("path",exported.toString(),"masterPassword","export-password"));
        rejects(()->vault.call("account.export",json("path",exported.toString(),"masterPassword","export-password")),"Never overwrite exports");
        vault.close();check(vault.list().isEmpty(),"Lock erases snapshots");rejects(()->vault.api(accountId),"Locked session inaccessible");
        rejects(()->vault.call("account.unlock",json("masterPassword","incorrect")),"Wrong master password rejected");
        vault.call("account.unlock",json("masterPassword","synthetic-master-password"));check(vault.api(accountId).getSid().equals("synthetic-session-secret"),"Persisted session restored");
        vault.call("account.remove",json("accountId",accountId));check(vault.list().isEmpty(),"Remove account");
        vault.call("account.import",json("path",exported.toString(),"masterPassword","export-password"));check(vault.list().size()==1,"Import account");
        vault.call("account.import",json("path",exported.toString(),"masterPassword","export-password"));check(vault.list().size()==1,"Import deduplicates accounts");
        twoFactor.set(true);Object second=vault.call("account.login",json("email","test@example.invalid","password","synthetic-password"));
        vault.call("challenge.respond",json("id",JSON.valueToTree(second).path("challenge").path("id").asText(),"cancel",true));check(vault.challenges().isEmpty(),"Challenge cancellation");
        vault.close();
        JsonNode envelope=JSON.readTree(Files.readAllBytes(profile.resolve("accounts.vault")));byte[] ciphertext=Base64.getDecoder().decode(envelope.path("data").asText());ciphertext[0]^=1;
        ((com.fasterxml.jackson.databind.node.ObjectNode)envelope).put("data",Base64.getEncoder().encodeToString(ciphertext));Files.write(profile.resolve("accounts.vault"),JSON.writeValueAsBytes(envelope));
        rejects(()->vault.call("account.unlock",json("masterPassword","synthetic-master-password")),"Authenticated vault detects tampering");
    }
    private static void settings(Path root) throws Exception {
        Path profile=root.resolve("preferences");SettingsStore settings=new SettingsStore(profile);
        check(Boolean.FALSE.equals(settings.get().get("commandHookEnabled")),"Command hooks off by default");
        check(Boolean.FALSE.equals(settings.get().get("clipboardMonitoring")),"Clipboard off by default");
        rejects(()->settings.update(json("workerSlots",0)),"Reject invalid worker slots");
        rejects(()->settings.update(json("concurrency",1.5)),"Reject fractional concurrency");
        rejects(()->settings.update(json("unknown",true)),"Reject unknown setting");
        settings.update(json("proxyEnabled",true,"proxyHost","localhost","proxyPassword","synthetic-proxy-secret","proxyUsername","synthetic-proxy-user"));
        check(!JSON.writeValueAsString(settings.get()).contains("synthetic-proxy"),"Settings snapshot hides credentials");
        check(!new String(Files.readAllBytes(profile.resolve("settings.json")),"UTF-8").contains("synthetic-proxy"),"Settings never persist proxy credentials");
        check(settings.raw().get("proxyPassword").equals("synthetic-proxy-secret"),"Runtime proxy auth remains usable");
        check(new SettingsStore(profile).raw().get("proxyPassword").equals(""),"Proxy auth is session only");
        rejects(()->settings.update(json("smartProxyList",Arrays.asList("http://user:secret@host:8080"))),"Reject credentials embedded in proxy list");
        settings.update(json("commandHook",Arrays.asList("/usr/bin/true"),"commandHookEnabled",true,"clipboardMonitoring",true));
        Path export=root.resolve("settings-export.json");settings.call("settings.export",json("path",export.toString()));settings.call("settings.import",json("path",export.toString()));
        check(Boolean.FALSE.equals(settings.get().get("commandHookEnabled")) && Boolean.FALSE.equals(settings.get().get("clipboardMonitoring")),"Import cannot enable external effects");
    }
    private static JsonNode waitTask(FileUtilities utilities,Object started) throws Exception {
        String id=JSON.valueToTree(started).path("id").asText();long deadline=System.nanoTime()+10000000000L;
        while(System.nanoTime()<deadline){JsonNode status=JSON.valueToTree(utilities.call("utility.status",json("id",id)));String state=status.path("status").asText();if(!state.equals("running") && !state.equals("queued"))return status;Thread.sleep(5);}throw new AssertionError("Utility timeout");
    }
    private static void utilities(Path root) throws Exception {
        Path parts=Files.createDirectory(root.resolve("parts")),input=root.resolve("payload.bin");byte[] bytes=new byte[1025];new Random(42).nextBytes(bytes);Files.write(input,bytes);
        try(FileUtilities utility=new FileUtilities()) {
            JsonNode split=waitTask(utility,utility.call("utility.split",json("path",input.toString(),"outputDirectory",parts.toString(),"partBytes",256)));
            check(split.path("status").asText().equals("completed"),"Split completes");check(split.path("outputs").size()==5,"Split handles final short chunk");
            List<String> paths=new ArrayList<>();for(JsonNode p:split.path("outputs"))paths.add(p.asText());
            Path output=root.resolve("joined.bin");JsonNode merge=waitTask(utility,utility.call("utility.merge",json("parts",paths,"outputPath",output.toString())));
            check(merge.path("status").asText().equals("completed") && Arrays.equals(bytes,Files.readAllBytes(output)),"Split merge preserves exact bytes");
            rejects(()->utility.call("utility.merge",json("parts",paths,"outputPath",output.toString())),"Merge rejects existing output");
            JsonNode collision=waitTask(utility,utility.call("utility.split",json("path",input.toString(),"outputDirectory",parts.toString(),"partBytes",256)));
            check(collision.path("status").asText().equals("failed"),"Split never overwrites output");check(Files.size(parts.resolve("payload.bin.part00001"))==256,"Existing split remains intact");
            rejects(()->utility.call("utility.merge",json("parts",Arrays.asList(paths.get(0),paths.get(0)),"outputPath",root.resolve("duplicate.bin").toString())),"Merge rejects duplicate inputs");
            Path empty=root.resolve("empty.bin");Files.write(empty,new byte[0]);JsonNode emptySplit=waitTask(utility,utility.call("utility.split",json("path",empty.toString(),"outputDirectory",parts.toString(),"partBytes",1)));
            check(emptySplit.path("status").asText().equals("completed") && Files.size(Paths.get(emptySplit.path("outputs").get(0).asText()))==0,"Empty file split works");
        }
        final FileUtilities[] holder=new FileUtilities[1];holder[0]=new FileUtilities(event->{try{JsonNode value=JSON.valueToTree(event).path("utility");if(value.path("status").asText().equals("running"))holder[0].call("utility.cancel",json("id",value.path("id").asText()));}catch(Exception ex){throw new RuntimeException(ex);}});
        try(FileUtilities utility=holder[0]){Path cancelled=root.resolve("cancelled.bin");JsonNode result=waitTask(utility,utility.call("utility.merge",json("parts",Arrays.asList(input.toString()),"outputPath",cancelled.toString())));check(result.path("status").asText().equals("cancelled") && !Files.exists(cancelled),"Cancellation does not publish output");}
    }
}
