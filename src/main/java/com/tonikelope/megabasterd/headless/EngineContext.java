package com.tonikelope.megabasterd.headless;
import com.fasterxml.jackson.databind.JsonNode;
import com.tonikelope.megabasterd.*;
import java.io.*;
import java.net.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import static com.tonikelope.megabasterd.headless.EngineMain.*;

/** One independent engine profile, durable state machine and lifecycle. No UI singleton. */
public final class EngineContext implements AutoCloseable {
    public final Path profile;
    public final AccountVault accounts;
    public final SettingsStore settings;
    public final FileUtilities utilities;
    public volatile boolean closed;
    final Map<String,TransferGroup> groups=new ConcurrentHashMap<>();
    final Map<String,Object> startLocks=new ConcurrentHashMap<>();
    static final class LinkChallenge {String id=UUID.randomUUID().toString();List<String> links;long expires=System.currentTimeMillis()+300000;}
    final Map<String,LinkChallenge> linkChallenges=new ConcurrentHashMap<>();
    final Map<String,Transfer> transfers=new ConcurrentHashMap<>();
    final Map<String,LinkResolver.Resolution> resolutions=new ConcurrentHashMap<>();
    final Consumer<Map<String,Object>> events;
    final EngineLog log;
    final ScheduledExecutorService scheduler=Executors.newSingleThreadScheduledExecutor();
    final ExecutorService workers=Executors.newCachedThreadPool();
    final TransferRunner runner;
    final java.util.function.Supplier<MegaAPI> anonymousApi;
    final java.util.function.Function<String,MegaAPI> accountApi;
    final StreamSessions streams;
    private final FileChannel lockChannel;
    private final FileLock profileLock;
    private final Object rateLock=new Object();
    private final Map<String,Long> nextBytes=new HashMap<>();
    private final Map<HttpURLConnection,String> connectionProxies=Collections.synchronizedMap(new WeakHashMap<>());
    private final ThreadLocal<String[]> slotProxy=new ThreadLocal<>();
    private long lastCheckpoint;
    private final java.util.concurrent.locks.ReentrantReadWriteLock lifecycle=new java.util.concurrent.locks.ReentrantReadWriteLock(true);
    private final java.util.concurrent.atomic.AtomicInteger activeOperations=new java.util.concurrent.atomic.AtomicInteger();
    public EngineContext(Path directory,Consumer<Map<String,Object>> events) throws Exception { this(directory,events,MegaAPI::new); }
    EngineContext(Path directory,Consumer<Map<String,Object>> events,java.util.function.Supplier<MegaAPI> anonymousApi) throws Exception { this(directory,events,anonymousApi,null); }
    EngineContext(Path directory,Consumer<Map<String,Object>> events,java.util.function.Supplier<MegaAPI> anonymousApi,java.util.function.Function<String,MegaAPI> accountApi) throws Exception {
        this.anonymousApi=anonymousApi;this.accountApi=accountApi;
        profile=directory.toAbsolutePath().normalize();privateDirectory(profile);
        lockChannel=FileChannel.open(profile.resolve("engine.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);
        profileLock=lockChannel.tryLock();if(profileLock==null)throw new RpcException(-32020,"This MEGA profile is already in use");
        log=new EngineLog(profile);this.events=event->{log.append(event);events.accept(event);};
        Path temp=profile.resolve("cache");privateDirectory(temp);
        System.setProperty("java.io.tmpdir",temp.toString());MainPanel.MEGABASTERD_HOME_DIR=profile.toString();privateDirectory(profile.resolve(".megabasterd"+MainPanel.VERSION));DBTools.setupSqliteTables();
        accounts=new AccountVault(profile);settings=new SettingsStore(profile);utilities=new FileUtilities(this.events);
        runner=new TransferRunner(this);streams=new StreamSessions(this);
        load();applySettings();
        scheduler.scheduleWithFixedDelay(this::schedule,0,200,TimeUnit.MILLISECONDS);
    }
    static void privateDirectory(Path path) throws IOException {
        Files.createDirectories(path);try {Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rwx------"));}catch(UnsupportedOperationException ignored){}
    }
    static void privateFile(Path path) throws IOException {try {Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));}catch(UnsupportedOperationException ignored){}}
    public Object call(String method,JsonNode p) throws Exception {
        boolean shutdown=method.equals("engine.shutdown");java.util.concurrent.locks.Lock lock=shutdown?lifecycle.writeLock():lifecycle.readLock();
        lock.lockInterruptibly();
        try {activeOperations.incrementAndGet();if(closed&&!shutdown)throw new RpcException(-32022,"Engine is shutting down");return dispatch(method,p);}
        finally{activeOperations.decrementAndGet();lock.unlock();}
    }
    Object dispatch(String method,JsonNode p) throws Exception {
        switch(method) {
            case "engine.handshake": case "engine.hello":
                if(p.has("protocolVersion")&&p.path("protocolVersion").asInt()!=1)throw new RpcException(-32021,"Unsupported protocol version");
                return map("protocolVersion",1,"dataVersion",1,"engineVersion","8.58-anydown.1","upstreamVersion","8.58","capabilities",Arrays.asList("engine.handshake","engine.snapshot","engine.shutdown","engine.logs","transfer.history.export","transfer.resolve","download.start","upload.start","transfer.list","transfer.pause","transfer.resume","transfer.cancel","transfer.retry","transfer.reorder","transfer.rate","transfer.publicLink","settings.get","settings.update","settings.import","settings.export","account.list","account.folders","account.elc.add","account.login","account.remove","account.lock","account.unlock","account.import","account.export","challenge.respond","stream.start","stream.stop","stream.list","utility.split","utility.merge","utility.list","utility.status","utility.cancel"),"features",Arrays.asList("folders","resume","integrity","proxies"));
            case "engine.snapshot":case "engine.status":return snapshot();
            case "engine.logs":return map("entries",log.list(p.path("limit").asInt(100)));
            case "transfer.history.export":return exportHistory(p);
            case "engine.shutdown":close();return map("shutdown",true);
            case "transfer.resolve": return resolveRequest(p);
            case "transfers.list":case "transfer.list":return snapshots();
            case "download.start": synchronized(startLocks.computeIfAbsent(required(p,"id"),id->new Object())) {return startDownloads(p);}
            case "upload.start": synchronized(startLocks.computeIfAbsent(required(p,"id"),id->new Object())) {return startUploads(p);}
            case "transfer.pause":case "transfer.resume":case "transfer.cancel":case "transfer.retry":case "transfer.reorder":return control(method,p);
            case "transfer.rate": return rate(p);
            case "transfer.publicLink":return publicLink(p);
            case "account.folders":return map("folders",api(required(p,"accountId")).getOwnFoldersHeadless());
            case "settings.get":return settings.get();
            case "settings.update":settings.update(p.has("settings")?p.path("settings"):p);applySettings();return settings.get();
            case "settings.export":case "settings.import":Object settingResult=settings.call(method,p);applySettings();return settingResult;
            case "stream.start":return streams.start(p);
            case "stream.stop":return streams.stop(required(p,"id"));
            case "stream.list":return streams.snapshot();
            default:
                if(method.equals("challenge.respond")&&linkChallenges.containsKey(p.path("id").asText()))return answerLinkChallenge(p);
                if(method.startsWith("account.")||method.equals("challenge.respond"))return accounts.call(method,p);
                if(method.startsWith("utility."))return utilities.call(method,p);
                throw new RpcException(-32601,"Unknown engine method");
        }
    }
    MegaAPI api(String accountId) throws Exception {return accountId==null?anonymousApi.get():accountApi!=null?accountApi.apply(accountId):accounts.api(accountId);}
    static String required(JsonNode p,String key) throws RpcException {String value=p.path(key).asText("");if(value.isEmpty())throw new RpcException(-32602,key+" is required");return value;}
    Object resolveRequest(JsonNode p) throws Exception {
        List<String> links;
        if(p.has("containerData")||p.has("containerPath")){
            String data;if(p.has("containerPath")){Path path=Paths.get(required(p,"containerPath"));if(Files.size(path)>2*1024*1024)throw new RpcException(-32602,"Container exceeds size limit");data=Files.readString(path);}else data=required(p,"containerData");
            links=new ArrayList<>(HeadlessDlcDecoder.decrypt(data));
        }else links=Arrays.asList(required(p,"url").trim().split("\\s+"));
        return resolveOrChallenge(links);
    }
    Object resolveOrChallenge(List<String> links)throws Exception {
        try{return resolveMany(links,null).snapshot();}catch(RpcException ex){if(ex.code!=-32030)throw ex;LinkChallenge challenge=new LinkChallenge();challenge.links=new ArrayList<>(links);linkChallenges.put(challenge.id,challenge);return map("challenge",linkChallengeSnapshot(challenge));}
    }
    Map<String,Object> linkChallengeSnapshot(LinkChallenge c){return map("id",c.id,"kind","linkPassword","message","Enter the password for this protected download link.","fields",Collections.singletonList("password"));}
    Object answerLinkChallenge(JsonNode p)throws Exception {
        String id=required(p,"id");LinkChallenge challenge=linkChallenges.get(id);if(challenge==null||challenge.expires<System.currentTimeMillis()){linkChallenges.remove(id);throw new RpcException(-32602,"Link challenge expired; resolve again");}
        if(p.path("cancel").asBoolean(false)){linkChallenges.remove(id);return map("cancelled",true);}
        String password=required(p,"value");LinkResolver.Resolution result=resolveMany(challenge.links,password);linkChallenges.remove(id);events.accept(map("type","resolution","resolution",result.snapshot()));return result.snapshot();
    }
    LinkResolver.Resolution resolve(String url) throws Exception {return resolveMany(Arrays.asList(url.trim().split("\\s+")),null);}
    LinkResolver.Resolution resolveMany(List<String> links,String password)throws Exception {
        if(links.isEmpty()||links.size()>1000)throw new RpcException(-32602,"Provide between one and 1000 links");
        LinkResolver.Resolution combined=new LinkResolver.Resolution();combined.resolutionId=UUID.randomUUID().toString();combined.type="folder";combined.name="MEGA links";
        for(String link:links){
            if(link.startsWith("mega://elc?")){JsonNode credentials=accounts.elcCredentials(HeadlessElcDecoder.host(link));LinkResolver.Resolution child=resolveMany(new ArrayList<>(HeadlessElcDecoder.decrypt(link,credentials)),password);combined.children.addAll(child.children);combined.size+=child.size;continue;}
            LinkResolver.Resolution r;
            URI uri=null;try{uri=URI.create(link);}catch(IllegalArgumentException ignored){}
            if(uri!=null&&uri.getHost()!=null&&!Arrays.asList("mega.nz","mega.co.nz").contains(uri.getHost().toLowerCase(Locale.ROOT).replaceFirst("^www\\.",""))){
                String[] metadata=HeadlessMegaCrypter.metadata(link,password);r=new LinkResolver.Resolution();r.resolutionId=UUID.randomUUID().toString();r.name=metadata[0];r.size=Long.parseLong(metadata[1]);r.type="file";
                LinkResolver.Node node=new LinkResolver.Node();node.id=UUID.randomUUID().toString();node.name=r.name;node.size=r.size;node.type="file";node.url=link;node.sourceKind="megacrypter";node.fileKey=metadata[2];node.passHash=metadata[3];node.noexpire=metadata[4];r.children.add(node);
            }else r=LinkResolver.resolve(link,bool("folderCache",true),anonymousApi.get());
            if(links.size()==1){resolutions.put(r.resolutionId,r);save();return r;}
            combined.children.addAll(r.children);combined.size+=r.size;
        }
        resolutions.put(combined.resolutionId,combined);save();return combined;
    }
    Object startDownloads(JsonNode p) throws Exception {
        String id=required(p,"id");validateId(id);
        if(groups.containsKey(id)&&groups.get(id).complete)return groupSnapshot(groups.get(id));
        if(transfers.containsKey(id))return map("id",id,"transfers",Collections.singletonList(transfers.get(id).snapshot()));
        LinkResolver.Resolution r=p.has("resolutionId")?resolutions.get(p.path("resolutionId").asText()):resolve(required(p,"url"));
        if(r==null)throw new RpcException(-32602,"Resolution expired; resolve the link again");
        String directory=required(p,"directory");Set<String> selected=new HashSet<>();
        if(p.has("nodeId"))selected.add(p.path("nodeId").asText());
        if(p.has("nodeIds")){if(!p.path("nodeIds").isArray())throw new RpcException(-32602,"nodeIds must be an array");p.path("nodeIds").forEach(n->selected.add(n.asText()));}
        List<LinkResolver.Node> files=new ArrayList<>();
        for(LinkResolver.Node n:r.children)if(n.type.equals("file")&&(selected.isEmpty()||selected.contains(n.id)||ancestorSelected(n,r,selected)))files.add(n);
        if(files.isEmpty())throw new RpcException(-32602,"Select at least one file");
        List<Object> added=new ArrayList<>();
        for(LinkResolver.Node n:files) {
            String transferId=files.size()==1?id:id+"-"+UUID.nameUUIDFromBytes(n.id.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Transfer t=transfers.get(transferId);
            if(t==null){t=new Transfer();t.id=transferId;t.name=LinkResolver.relativeName(n,r);t.url=n.url;t.sourceKind=n.sourceKind;t.fileKey=n.fileKey;t.passHash=n.passHash;t.noexpire=n.noexpire;t.totalBytes=n.size;t.directory=Paths.get(directory).toAbsolutePath().normalize().toString();t.order=transfers.size();t.rateLimitBytesPerSecond=p.hasNonNull("rateLimitBytesPerSecond")?p.path("rateLimitBytesPerSecond").asLong():null;t.accountId=p.hasNonNull("accountId")?p.path("accountId").asText():null;transfers.put(t.id,t);}
            added.add(t.snapshot());
        }
        TransferGroup group=new TransferGroup();group.id=id;group.complete=true;for(Object item:added)group.children.add(((Map<?,?>)item).get("id").toString());groups.put(id,group);
        save();return map("id",id,"transfers",added);
    }
    boolean ancestorSelected(LinkResolver.Node n,LinkResolver.Resolution r,Set<String> selected) {
        Map<String,LinkResolver.Node> nodes=new HashMap<>();for(LinkResolver.Node node:r.children)nodes.put(node.id,node);
        Set<String> seen=new HashSet<>();while(n.parentId!=null&&seen.add(n.parentId)){if(selected.contains(n.parentId))return true;n=nodes.get(n.parentId);if(n==null)return false;}return false;
    }
    Object startUploads(JsonNode p) throws Exception {
        String id=required(p,"id");validateId(id);if(transfers.containsKey(id))return map("id",id,"transfers",Collections.singletonList(transfers.get(id).snapshot()));
        TransferGroup group=groups.get(id);if(group!=null&&group.complete)return groupSnapshot(group);
        Path path=Paths.get(required(p,"path")).toRealPath();String accountId=required(p,"accountId");MegaAPI api=api(accountId);
        String parent=p.hasNonNull("parentNode")?p.path("parentNode").asText():api.getRoot_id();
        if(!Files.isDirectory(path)){Transfer t=queueUpload(id,path,accountId,parent,p);save();return map("id",id,"transfers",Collections.singletonList(t.snapshot()));}
        if(group==null){group=new TransferGroup();group.id=id;group.path=path.toString();group.accountId=accountId;group.parentNode=parent;if(p.path("publicLink").asBoolean(false))group.shareKey=MiscTools.Bin2UrlBASE64(api.genShareKey());groups.put(id,group);save();}
        else if(!group.path.equals(path.toString())||!group.accountId.equals(accountId)||!Objects.equals(group.parentNode,parent))throw new RpcException(-32602,"Transfer group id already belongs to another upload");
        Map<Path,String> parents=new HashMap<>();parents.put(path.getParent(),parent);
        try(java.util.stream.Stream<Path> walk=Files.walk(path)) {
            for(Path file:(Iterable<Path>)walk.sorted()::iterator) {
                if(Files.isSymbolicLink(file))continue;
                String relative=path.relativize(file).toString();
                if(Files.isDirectory(file)) {
                    String remote=group.folders.get(relative);
                    if(remote==null){String encoded=group.folderKeys.get(relative);if(encoded==null){encoded=MiscTools.Bin2UrlBASE64(api.genFolderKey());group.folderKeys.put(relative,encoded);save();}
                        byte[] key=MiscTools.UrlBASE642Bin(encoded);
                        remote=api.findOwnNodeHeadless(parents.get(file.getParent()),file.getFileName().toString(),1,key);
                        if(remote==null)remote=group.shareKey!=null&&!relative.isEmpty()?api.createDirHeadless(file.getFileName().toString(),parents.get(file.getParent()),key,group.folders.get(""),MiscTools.UrlBASE642Bin(group.shareKey)):api.createDirHeadless(file.getFileName().toString(),parents.get(file.getParent()),key);
                        if(remote==null)throw new RpcException(-32015,"Cannot create upload folder");group.folders.put(relative,remote);save();
                    }
                    if(relative.isEmpty()&&group.shareKey!=null&&group.publicLink==null){byte[] rootKey=MiscTools.UrlBASE642Bin(group.folderKeys.get("")),shareKey=MiscTools.UrlBASE642Bin(group.shareKey);if(api.shareFolder(remote,rootKey,shareKey)==null)throw new RpcException(-32015,"MEGA folder sharing failed");group.publicLink=api.getPublicFolderLink(remote,shareKey);save();}
                    parents.put(file,remote);
                } else if(Files.isRegularFile(file)) {
                    String child=id+"-"+UUID.nameUUIDFromBytes(relative.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    Transfer upload=queueUpload(child,file,accountId,parents.get(file.getParent()),p);upload.rootNode=group.folders.get("");upload.shareKey=group.shareKey;if(!group.children.contains(child))group.children.add(child);save();
                }
            }
        }
        if(group.children.isEmpty()){Transfer empty=new Transfer();empty.id=id;empty.name=path.getFileName().toString();empty.direction="upload";empty.status="completed";empty.accountId=accountId;empty.publicLink=group.publicLink;transfers.put(id,empty);group.children.add(id);}
        group.complete=true;save();return groupSnapshot(group);
    }
    Object groupSnapshot(TransferGroup group){List<Object> result=new ArrayList<>();for(String id:group.children){Transfer t=transfers.get(id);if(t!=null)result.add(t.snapshot());}return map("id",group.id,"transfers",result);}
    Transfer queueUpload(String id,Path path,String accountId,String parent,JsonNode p) throws Exception {
        Transfer existing=transfers.get(id);if(existing!=null)return existing;
        Transfer t=new Transfer();t.id=id;t.direction="upload";t.name=path.getFileName().toString();t.path=path.toString();t.totalBytes=Files.size(path);t.modifiedTime=Files.getLastModifiedTime(path).toMillis();t.accountId=accountId;t.parentNode=parent;t.publicLinkEnabled=p.path("publicLink").asBoolean(false);t.thumbnailEnabled=p.path("thumbnail").asBoolean(true);t.order=transfers.size();t.rateLimitBytesPerSecond=p.hasNonNull("rateLimitBytesPerSecond")?p.path("rateLimitBytesPerSecond").asLong():null;transfers.put(id,t);return t;
    }
    static void validateId(String id) throws RpcException {if(!id.matches("[A-Za-z0-9_-]{1,128}"))throw new RpcException(-32602,"Transfer id is invalid");}
    synchronized Object control(String method,JsonNode p) throws Exception {
        Transfer t=transfers.get(required(p,"id"));if(t==null)throw new RpcException(-32602,"Transfer not found");
        if(method.equals("transfer.reorder")){t.order=p.path("order").asInt();}
        else if(method.equals("transfer.pause")){if(t.status.equals("completed")||t.status.equals("cancelled"))return t.snapshot();t.stop=true;t.status="paused";if(t.worker!=null)t.worker.interrupt();}
        else if(method.equals("transfer.cancel")){if(t.status.equals("completed"))return t.snapshot();t.stop=true;t.status="cancelled";if(t.worker!=null)t.worker.interrupt();else if(!bool("keepTemporaryFiles",true)&&t.temporaryPath!=null){Files.deleteIfExists(Paths.get(t.temporaryPath));t.completedChunks.clear();t.completedBytes=0;}}
        else {if(t.status.equals("completed"))return t.snapshot();if(t.running)throw new RpcException(-32022,"Transfer is still stopping; retry shortly");t.stop=false;t.error=null;t.status="queued";}
        changed(t);return t.snapshot();
    }
    Object rate(JsonNode p) throws Exception {
        Transfer t=transfers.get(required(p,"id"));if(t==null)throw new RpcException(-32602,"Transfer not found");
        JsonNode value=p.get("bytesPerSecond");if(value==null||(!value.isNull()&&(!value.isIntegralNumber()||!value.canConvertToLong()||value.asLong()<0)))throw new RpcException(-32602,"bytesPerSecond must be null or a non-negative integer");
        synchronized(t){t.rateLimitBytesPerSecond=value.isNull()?null:value.asLong();t.nextRateNanos=0;}save();return map("id",t.id,"bytesPerSecond",t.rateLimitBytesPerSecond);
    }
    synchronized Object publicLink(JsonNode p) throws Exception {String id=required(p,"id");TransferGroup group=groups.get(id);if(group!=null&&group.publicLink!=null)return map("url",group.publicLink);Transfer t=transfers.get(id);if(t==null||t.publicLink==null)throw new RpcException(-32602,"No public upload link is available");return map("url",t.publicLink);}
    void schedule() {
        try {
            if(closed)return;
            List<Transfer> queue=new ArrayList<>(transfers.values());queue.sort(Comparator.comparingInt(t->t.order));
            int running=(int)queue.stream().filter(t->t.running).count();
            int uploading=(int)queue.stream().filter(t->t.running&&t.direction.equals("upload")).count();
            for(Transfer t:queue) {
                if(running>=integer("concurrency",3))break;
                if(!t.status.equals("queued")||t.running)continue;
                if(t.direction.equals("upload")&&uploading>=integer("maxUploads",3))continue;
                synchronized(this){if(!t.status.equals("queued")||t.running)continue;t.running=true;t.stop=false;t.status="running";}running++;if(t.direction.equals("upload"))uploading++;
                workers.submit(()->run(t));
            }
            if(System.currentTimeMillis()-lastCheckpoint>5000){synchronized(this){save();}}
        }catch(Exception e){events.accept(map("type","engineError","message","Engine checkpoint failed"));}
    }
    void run(Transfer t) {
        t.worker=Thread.currentThread();
        try {changed(t);if(t.direction.equals("upload"))runner.upload(t);else runner.download(t);if(!t.stop){t.status="completed";completionHook(t);}}
        catch(Exception e){Throwable cause=e instanceof ExecutionException?e.getCause():e;if(t.stop||closed||cause instanceof InterruptedException){if(!t.status.equals("cancelled"))t.status="paused";}else{t.status="failed";t.error=cause instanceof RpcException?cause.getMessage():"Transfer failed ("+cause.getClass().getSimpleName()+")";}}
        finally {if(t.status.equals("cancelled")&&!bool("keepTemporaryFiles",true)&&t.temporaryPath!=null){try{Files.deleteIfExists(Paths.get(t.temporaryPath));t.completedChunks.clear();t.completedBytes=0;}catch(IOException ex){t.error="Unable to remove temporary file";}}t.worker=null;t.running=false;t.speedBytesPerSecond=0;changed(t);Thread.interrupted();}
    }
    void completionHook(Transfer t) {
        if(!bool("commandHookEnabled",false))return;
        Object value=settings.raw().get("commandHook");if(!(value instanceof List)||((List)value).isEmpty())return;
        try {
            List<String> command=new ArrayList<>();for(Object part:(List)value)command.add(part.toString());
            ProcessBuilder builder=new ProcessBuilder(command);builder.environment().put("ANYDOWN_TRANSFER_ID",t.id);builder.environment().put("ANYDOWN_TRANSFER_DIRECTION",t.direction);
            if(t.outputPath!=null)builder.environment().put("ANYDOWN_OUTPUT_PATH",t.outputPath);
            builder.redirectOutput(ProcessBuilder.Redirect.DISCARD);builder.redirectError(ProcessBuilder.Redirect.DISCARD);
            Process process=builder.start();if(!process.waitFor(30,TimeUnit.SECONDS)){process.destroyForcibly();events.accept(map("type","hook","id",t.id,"status","timedOut"));}
            else events.accept(map("type","hook","id",t.id,"exitCode",process.exitValue()));
        }catch(Exception e){events.accept(map("type","hook","id",t.id,"status","failed"));}
    }
    public void changed(Transfer t) {try{synchronized(this){save();}events.accept(map("type","transfer","transfer",t.snapshot()));}catch(Exception e){t.stop=true;t.status="failed";t.error="Cannot persist transfer checkpoint";events.accept(map("type","transfer","transfer",t.snapshot()));}}
    Object exportHistory(JsonNode p) throws Exception {
        String direction=p.path("direction").asText("upload");if(!Arrays.asList("upload","download").contains(direction))throw new RpcException(-32602,"direction must be upload or download");
        List<Object> result=new ArrayList<>();for(Transfer t:transfers.values())if(t.direction.equals(direction))result.add(t.snapshot());
        AccountVault.writePrivate(Paths.get(required(p,"path")),JSON.writeValueAsBytes(map("version",1,"transfers",result)),false);
        return map("exported",true,"count",result.size());
    }
    List<Object> snapshots(){List<Object> result=new ArrayList<>();transfers.values().stream().sorted(Comparator.comparingInt(t->t.order)).forEach(t->result.add(t.snapshot()));return result;}
    List<Object> challengeSnapshots(){List<Object> result=new ArrayList<>(accounts.challenges());linkChallenges.values().removeIf(c->c.expires<System.currentTimeMillis());for(LinkChallenge c:linkChallenges.values())result.add(linkChallengeSnapshot(c));return result;}
    Map<String,Object> snapshot(){return map("protocolVersion",1,"engineVersion","8.58-anydown.1","transfers",snapshots(),"accounts",accounts.list(),"challenges",challengeSnapshots(),"settings",settings.get(),"streams",streams.snapshot(),"utilities",utilities.list(),"locked",accounts.isLocked(),"activeOperations",Math.max(0,activeOperations.get()-1));}
    synchronized void load() throws Exception {
        Path file=profile.resolve("state.json");if(!Files.exists(file))return;JsonNode state=JSON.readTree(file.toFile());
        if(state.path("dataVersion").asInt()!=1)throw new RpcException(-32021,"Unsupported engine data version");
        for(JsonNode node:state.path("transfers")){Transfer t=JSON.treeToValue(node,Transfer.class);if(Arrays.asList("running","verifying","retrying").contains(t.status))t.status="queued";transfers.put(t.id,t);}
        for(JsonNode node:state.path("groups")){TransferGroup g=JSON.treeToValue(node,TransferGroup.class);groups.put(g.id,g);}
        for(JsonNode node:state.path("resolutions")){LinkResolver.Resolution r=JSON.treeToValue(node,LinkResolver.Resolution.class);resolutions.put(r.resolutionId,r);}
    }
    synchronized void save() throws IOException {
        Path temp=profile.resolve("state.json.tmp");Files.write(temp,JSON.writeValueAsBytes(map("dataVersion",1,"transfers",transfers.values(),"resolutions",resolutions.values(),"groups",groups.values())),StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING);privateFile(temp);
        try(FileChannel channel=FileChannel.open(temp,StandardOpenOption.WRITE)){channel.force(true);}
        Files.move(temp,profile.resolve("state.json"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);lastCheckpoint=System.currentTimeMillis();
    }
    public int integer(String key,int fallback){Object value=settings.raw().get(key);return value instanceof Number?((Number)value).intValue():fallback;}
    public long number(String key,long fallback){Object value=settings.raw().get(key);return value instanceof Number?((Number)value).longValue():fallback;}
    public boolean bool(String key,boolean fallback){Object value=settings.raw().get(key);return value instanceof Boolean?(Boolean)value:fallback;}
    String string(String key){return Objects.toString(settings.raw().get(key),"");}
    synchronized void applySettings() throws Exception {
        MainPanel.configureHeadlessProxy(bool("proxyEnabled",false),string("proxyHost"),integer("proxyPort",8080),string("proxyUsername"),string("proxyPassword"),bool("smartProxyEnabled",false));
        DBTools.insertSettingValue("smartproxy_ban_time",Integer.toString(integer("smartProxyBanSeconds",300)));
        DBTools.insertSettingValue("smartproxy_timeout",Integer.toString(integer("smartProxyTimeoutSeconds",30)));
        DBTools.insertSettingValue("smartproxy_autorefresh_time",Integer.toString(integer("smartProxyRefreshMinutes",60)));
        DBTools.insertSettingValue("smart_proxy_509_recheck_window",Integer.toString(integer("smartProxyRecheckSeconds",300)));
        DBTools.insertSettingValue("force_smart_proxy",bool("smartProxyForce",false)?"yes":"no");
        DBTools.insertSettingValue("random_proxy",bool("smartProxyRandom",true)?"yes":"no");
        DBTools.insertSettingValue("reset_slot_proxy",bool("smartProxyResetSlot",true)?"yes":"no");
        DBTools.insertSettingValue("custom_proxy_list",String.join("\n",(List<String>)settings.raw().get("smartProxyList")));DBTools.insertSettingValue("always_reload_mega_folders",bool("folderCache",true)?"no":"yes");
        if(bool("smartProxyEnabled",false)){SmartMegaProxyManager manager=MainPanel.getProxy_manager();if(manager==null)MainPanel.setProxy_manager(new SmartMegaProxyManager(()->closed,message->events.accept(map("type","proxy","message",message))));else{manager.refreshSmartProxySettings();workers.submit(manager::refreshProxyList);}}
    }
    HttpURLConnection open(String value,boolean smart) throws IOException {
        URL url=new URL(value);if(!Arrays.asList("http","https").contains(url.getProtocol()))throw new IOException("Invalid transfer protocol");
        Proxy proxy=Proxy.NO_PROXY;String usedProxy=null;
        if(bool("proxyEnabled",false))proxy=new Proxy(Proxy.Type.HTTP,new InetSocketAddress(string("proxyHost"),integer("proxyPort",8080)));
        else if((smart||bool("smartProxyForce",false))&&bool("smartProxyEnabled",false)&&MainPanel.getProxy_manager()!=null){
            String[] selected=bool("smartProxyResetSlot",true)?null:slotProxy.get();if(selected==null)selected=MainPanel.getProxy_manager().getProxy(new ArrayList<>());
            if(selected!=null){String address=selected[0];int colon=address.lastIndexOf(':');String host=address.substring(0,colon);if(host.startsWith("[")&&host.endsWith("]"))host=host.substring(1,host.length()-1);proxy=new Proxy("socks".equals(selected[1])?Proxy.Type.SOCKS:Proxy.Type.HTTP,new InetSocketAddress(host,Integer.parseInt(address.substring(colon+1))));usedProxy=address;slotProxy.set(selected);}
            else throw new IOException("No usable SmartProxy");
        }
        HttpURLConnection connection=(HttpURLConnection)url.openConnection(proxy);connection.setConnectTimeout(15000);connection.setReadTimeout(30000);connection.setInstanceFollowRedirects(false);connection.setRequestProperty("User-Agent",MainPanel.DEFAULT_USER_AGENT);
        if(bool("proxyEnabled",false)&&!string("proxyUsername").isEmpty())connection.setRequestProperty("Proxy-Authorization","Basic "+Base64.getEncoder().encodeToString((string("proxyUsername")+":"+string("proxyPassword")).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        if(usedProxy!=null){connectionProxies.put(connection,usedProxy);connection.setConnectTimeout(integer("smartProxyTimeoutSeconds",30)*1000);connection.setReadTimeout(integer("smartProxyTimeoutSeconds",30)*1000);}
        return connection;
    }
    void connectionFailed(HttpURLConnection connection){String proxy=connectionProxies.remove(connection);if(proxy!=null&&MainPanel.getProxy_manager()!=null){MainPanel.getProxy_manager().blockProxy(proxy,"transfer error");slotProxy.remove();}}
    void awaitPayload(Transfer t) throws InterruptedException {while(t.rateLimitBytesPerSecond!=null&&t.rateLimitBytesPerSecond==0){runner.check(t);Thread.sleep(50);}}
    void throttle(Transfer t,String direction,int bytes) throws InterruptedException {
        long perWait=0;
        while(t.rateLimitBytesPerSecond!=null&&t.rateLimitBytesPerSecond==0){runner.check(t);Thread.sleep(50);}
        synchronized(t){
            long now=System.nanoTime();if(t.speedWindowNanos==0)t.speedWindowNanos=now;t.speedWindowBytes+=bytes;
            if(now-t.speedWindowNanos>=500_000_000L){t.speedBytesPerSecond=(long)(t.speedWindowBytes*1e9/(now-t.speedWindowNanos));t.speedWindowNanos=now;t.speedWindowBytes=0;}
            Long rate=t.rateLimitBytesPerSecond;if(rate!=null&&rate>0){long next=Math.max(now,t.nextRateNanos);perWait=next-now;t.nextRateNanos=next+(long)(bytes*1e9/rate);}
        }
        while(perWait>0){runner.check(t);long duration=Math.min(perWait,100_000_000);TimeUnit.NANOSECONDS.sleep(duration);perWait-=duration;}
        long limit=number(direction+"BytesPerSecond",0);if(limit<=0)return;long wait;
        synchronized(rateLock){long now=System.nanoTime(),next=Math.max(now,nextBytes.getOrDefault(direction,now));wait=next-now;nextBytes.put(direction,next+(long)(bytes*1_000_000_000.0/limit));}
        while(wait>0){runner.check(t);long duration=Math.min(wait,100_000_000);TimeUnit.NANOSECONDS.sleep(duration);wait-=duration;}
    }
    @Override public void close() {
        lifecycle.writeLock().lock();
        try {closeLocked();}finally{lifecycle.writeLock().unlock();}
    }
    private void closeLocked() {
        synchronized(this){if(closed)return;closed=true;}
        scheduler.shutdownNow();for(Transfer t:transfers.values())t.stop=true;
        workers.shutdownNow();streams.close();utilities.close();
        try {
            if(!workers.awaitTermination(45,TimeUnit.SECONDS))throw new IllegalStateException("Transfer workers did not quiesce");
            SmartMegaProxyManager proxy=MainPanel.getProxy_manager();if(proxy!=null){proxy.shutdownHeadless();MainPanel.setProxy_manager(null);}
            synchronized(this){save();}
            accounts.close();SqliteSingleton.getInstance().shutdown();profileLock.release();lockChannel.close();
        } catch(Exception ex) {
            // A failed quiescence must never be acknowledged as a profile safe for migration.
            events.accept(map("type","engineError","message","Engine did not quiesce safely"));
            throw new IllegalStateException("Engine did not quiesce safely",ex);
        }
    }
}
