/* AnyDown headless integration. GPL-3.0. */
package com.tonikelope.megabasterd.headless;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.*;
import java.util.*;
import static com.tonikelope.megabasterd.headless.EngineMain.*;

/** Validated engine preferences. Proxy credentials are session-only and never exported. */
public final class SettingsStore {
    private final Path file;
    private Map<String,Object> values=defaults();
    private static Map<String,Object> defaults() {
        return map("concurrency",3,"maxUploads",3,"workerSlots",6,
            "downloadBytesPerSecond",0L,"uploadBytesPerSecond",0L,
            "proxyEnabled",false,"proxyHost","","proxyPort",8080,"proxyUsername","","proxyPassword","",
            "smartProxyEnabled",false,"smartProxyList",new ArrayList<String>(),"smartProxyForce",false,"smartProxyRandom",true,"smartProxyResetSlot",true,
            "smartProxyBanSeconds",300,"smartProxyTimeoutSeconds",30,"smartProxyRefreshMinutes",60,"smartProxyRecheckSeconds",300,"folderCache",true,
            "commandHookEnabled",false,"commandHook",new ArrayList<String>(),"verifyIntegrity",true,"retryLimit",10,"clipboardMonitoring",false,
            "tempDirectory","","keepTemporaryFiles",true);
    }
    public SettingsStore(Path profile) throws Exception {
        Files.createDirectories(profile);file=profile.resolve("settings.json");
        if(Files.exists(file)) {
            if(Files.size(file)>1024*1024)throw new RpcException(-32602,"Settings file exceeds size limit");
            values=validated(JSON.readTree(Files.readAllBytes(file)),values);
        }
    }
    public synchronized Map<String,Object> get() {
        Map<String,Object> result=raw();result.put("proxyPassword","");result.put("proxyUsername","");
        result.put("proxyCredentialsConfigured",!String.valueOf(values.get("proxyPassword")).isEmpty());
        result.put("proxyCredentialPersistence","session");return result;
    }
    @SuppressWarnings("unchecked") public synchronized Map<String,Object> raw() { return JSON.convertValue(values,LinkedHashMap.class); }
    public synchronized Object getValue(String key) { return raw().get(key); }
    public synchronized Map<String,Object> update(JsonNode settings) throws Exception {
        Map<String,Object> next=validated(settings,values);Map<String,Object> disk=new LinkedHashMap<>(next);
        disk.remove("proxyPassword");disk.remove("proxyUsername");
        AccountVault.writePrivate(file,JSON.writeValueAsBytes(disk),true);values=next;return get();
    }
    public synchronized Object call(String method,JsonNode params) throws Exception {
        switch(method) {
            case "settings.get":return get();
            case "settings.update": return update(params.has("settings")?params.get("settings"):params);
            case "settings.export": {
                Path path=requiredPath(params);Map<String,Object> disk=raw();disk.remove("proxyPassword");disk.remove("proxyUsername");
                AccountVault.writePrivate(path,JSON.writeValueAsBytes(disk),false);return map("exported",true);
            }
            case "settings.import": {
                Path path=requiredPath(params);if(Files.size(path)>1024*1024)throw new RpcException(-32602,"Settings import exceeds size limit");
                JsonNode settings=JSON.readTree(Files.readAllBytes(path));
                // An imported configuration must not silently execute commands or monitor clipboard.
                if(settings.isObject()) { ((com.fasterxml.jackson.databind.node.ObjectNode)settings).put("commandHookEnabled",false);((com.fasterxml.jackson.databind.node.ObjectNode)settings).put("clipboardMonitoring",false); }
                return update(settings);
            }
            default:throw new RpcException(-32601,"Unknown settings method");
        }
    }
    private static Path requiredPath(JsonNode params) throws RpcException {
        if(!params.path("path").isTextual() || params.path("path").asText().isEmpty())throw new RpcException(-32602,"A file path is required");return Paths.get(params.path("path").asText());
    }
    private static Map<String,Object> validated(JsonNode settings,Map<String,Object> current) throws Exception {
        if(!settings.isObject())throw new RpcException(-32602,"Settings must be an object");
        Map<String,Object> next=new LinkedHashMap<>(current);Iterator<Map.Entry<String,JsonNode>> iterator=settings.fields();
        while(iterator.hasNext()) {
            Map.Entry<String,JsonNode> entry=iterator.next();String key=entry.getKey();JsonNode value=entry.getValue();
            if(!defaults().containsKey(key))throw new RpcException(-32602,"Unknown setting: "+key);
            switch(key) {
                case "concurrency":case "maxUploads": integer(value,key,1,64);next.put(key,value.intValue());break;
                case "smartProxyBanSeconds":integer(value,key,0,3600);next.put(key,value.intValue());break;
                case "smartProxyTimeoutSeconds":integer(value,key,3,120);next.put(key,value.intValue());break;
                case "smartProxyRefreshMinutes":integer(value,key,1,1440);next.put(key,value.intValue());break;
                case "smartProxyRecheckSeconds":integer(value,key,60,86400);next.put(key,value.intValue());break;
                case "retryLimit": integer(value,key,0,100);next.put(key,value.intValue());break;
                case "workerSlots": integer(value,key,1,32);next.put(key,value.intValue());break;
                case "proxyPort":integer(value,key,1,65535);next.put(key,value.intValue());break;
                case "downloadBytesPerSecond":case "uploadBytesPerSecond": integer(value,key,0,Long.MAX_VALUE);next.put(key,value.longValue());break;
                case "smartProxyForce":case "smartProxyRandom":case "smartProxyResetSlot":case "verifyIntegrity":case "proxyEnabled":case "smartProxyEnabled":case "folderCache":case "commandHookEnabled":case "clipboardMonitoring":case "keepTemporaryFiles":
                    if(!value.isBoolean())throw new RpcException(-32602,key+" must be boolean");next.put(key,value.booleanValue());break;
                case "smartProxyList":case "commandHook": {
                    if(key.equals("smartProxyList") && value.isTextual()) {
                        List<String> lines=new ArrayList<>();for(String line:value.asText().split("\\r?\\n")){if(!line.trim().isEmpty())lines.add(line.trim());}value=JSON.valueToTree(lines);
                    }
                    if(!value.isArray() || value.size()>(key.equals("smartProxyList")?1000:128))throw new RpcException(-32602,key+" must be a bounded list");
                    List<String> items=new ArrayList<>();for(JsonNode item:value){if(!item.isTextual() || item.asText().isEmpty() || item.asText().length()>4096 || item.asText().indexOf('\0')>=0)throw new RpcException(-32602,"Invalid "+key+" entry");
                        if(key.equals("smartProxyList")) validateProxy(item.asText());items.add(item.asText());}
                    next.put(key,items);break;
                }
                default:
                    if(!value.isTextual() || value.asText().length()>4096 || value.asText().indexOf('\0')>=0)throw new RpcException(-32602,key+" must be text");
                    next.put(key,value.asText());
            }
        }
        if(Boolean.TRUE.equals(next.get("proxyEnabled")) && String.valueOf(next.get("proxyHost")).trim().isEmpty())throw new RpcException(-32602,"Proxy host is required");
        String host=String.valueOf(next.get("proxyHost"));if(host.contains("/") || host.contains("@") || host.matches(".*\\s.*"))throw new RpcException(-32602,"Proxy host must be a hostname or IP address");
        if(Boolean.TRUE.equals(next.get("smartProxyEnabled")) && ((List<?>)next.get("smartProxyList")).isEmpty())throw new RpcException(-32602,"Configure at least one SmartProxy");
        if(Boolean.TRUE.equals(next.get("commandHookEnabled")) && ((List<?>)next.get("commandHook")).isEmpty())throw new RpcException(-32602,"Configure a completion command first");
        String temporary=String.valueOf(next.get("tempDirectory"));if(!temporary.isEmpty() && !Paths.get(temporary).isAbsolute())throw new RpcException(-32602,"Temporary directory must be an absolute path");
        return next;
    }
    private static void integer(JsonNode value,String name,long min,long max) throws RpcException {
        if(!value.isIntegralNumber() || !value.canConvertToLong() || value.longValue()<min || value.longValue()>max)throw new RpcException(-32602,"Invalid "+name);
    }
    private static void validateProxy(String proxy) throws RpcException {
        try {
            if(proxy.startsWith("#")){java.net.URI source=new java.net.URI(proxy.substring(1));if(!"https".equals(source.getScheme())||source.getHost()==null||source.getUserInfo()!=null)throw new Exception();return;}
            java.net.URI uri=new java.net.URI(proxy.contains("://")?proxy:"http://"+proxy);
            if(!Arrays.asList("http","socks5").contains(uri.getScheme()) || uri.getHost()==null || uri.getPort()<1 || uri.getPort()>65535 || uri.getUserInfo()!=null || uri.getQuery()!=null || uri.getFragment()!=null || (uri.getPath()!=null && !uri.getPath().isEmpty()))throw new Exception();
        } catch(Exception ex){throw new RpcException(-32602,"SmartProxy entries must be http://host:port or socks5://host:port without credentials");}
    }
}
