package com.tonikelope.megabasterd.headless;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.*;
import com.tonikelope.megabasterd.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Cipher;
import static com.tonikelope.megabasterd.CryptTools.*;
import static com.tonikelope.megabasterd.headless.EngineMain.*;

/** Opaque loopback URLs for decrypted ranges. No source URL or key leaves the process. */
public final class StreamSessions implements AutoCloseable {
    static final class Session {String id,url,key,name,source,accountId,sourceKind,passHash,noexpire;long size;Transfer throttle=new Transfer();}
    private final EngineContext context;
    private final Map<String,Session> sessions=new ConcurrentHashMap<>();
    private HttpServer server;
    private ExecutorService workers;
    StreamSessions(EngineContext context){this.context=context;}
    public synchronized Object start(JsonNode p) throws Exception {
        LinkResolver.Resolution resolution;
        if(p.has("resolutionId"))resolution=context.resolutions.get(p.path("resolutionId").asText());
        else resolution=context.resolve(EngineContext.required(p,"url"));
        if(resolution==null)throw new RpcException(-32602,"Resolve the MEGA link first");
        LinkResolver.Node node=null;
        for(LinkResolver.Node candidate:resolution.children)if(candidate.type.equals("file")&&(!p.has("nodeId")||p.path("nodeId").asText().equals(candidate.id))){if(node!=null&&!p.has("nodeId"))throw new RpcException(-32602,"Select one file to stream");node=candidate;}
        if(node==null)throw new RpcException(-32602,"No streamable file was selected");
        String accountId=p.hasNonNull("accountId")?p.path("accountId").asText():null;MegaAPI api=context.api(accountId);String[] metadata="megacrypter".equals(node.sourceKind)?new String[]{node.name,Long.toString(node.size),node.fileKey}:api.getMegaFileMetadata(node.url);
        Session session=new Session();session.id=UUID.randomUUID().toString();session.url="megacrypter".equals(node.sourceKind)?HeadlessMegaCrypter.downloadUrl(node.url,node.passHash,node.noexpire,null):api.getMegaFileDownloadUrl(node.url);session.sourceKind=node.sourceKind;session.passHash=node.passHash;session.noexpire=node.noexpire;session.key=metadata[2];session.name=node.name;session.size=node.size;session.source=node.url;session.accountId=accountId;session.throttle.id=session.id;
        if(server==null){server=HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),0),16);workers=Executors.newFixedThreadPool(4);server.setExecutor(workers);server.createContext("/stream/",this::serve);server.start();}
        sessions.put(session.id,session);
        return map("id",session.id,"url","http://127.0.0.1:"+server.getAddress().getPort()+"/stream/"+session.id,"name",session.name,"size",session.size);
    }
    public synchronized Object stop(String id){Session removed=sessions.remove(id);if(removed!=null)removed.throttle.stop=true;return map("id",id,"stopped",true);}
    public List<Object> snapshot(){List<Object> result=new ArrayList<>();for(Session s:sessions.values())result.add(map("id",s.id,"name",s.name,"size",s.size));return result;}
    void serve(HttpExchange exchange) throws IOException {
        HttpURLConnection upstream=null;String stage="request";
        try {
            if(!exchange.getRemoteAddress().getAddress().isLoopbackAddress()){exchange.sendResponseHeaders(403,-1);return;}
            String host=exchange.getRequestHeaders().getFirst("Host");
            if(host==null||!host.equals("127.0.0.1:"+server.getAddress().getPort())){exchange.sendResponseHeaders(403,-1);return;}
            if(!Arrays.asList("GET","HEAD").contains(exchange.getRequestMethod())){exchange.sendResponseHeaders(405,-1);return;}
            String id=exchange.getRequestURI().getPath().substring("/stream/".length());Session s=sessions.get(id);
            if(s==null){exchange.sendResponseHeaders(404,-1);return;}
            long[] range=parseRange(exchange.getRequestHeaders().getFirst("Range"),s.size);
            if(range==null){exchange.getResponseHeaders().set("Content-Range","bytes */"+s.size);exchange.sendResponseHeaders(416,-1);return;}
            long start=range[0],end=range[1],length=s.size==0?0:end-start+1;
            Headers headers=exchange.getResponseHeaders();headers.set("Accept-Ranges","bytes");headers.set("Cache-Control","no-store");headers.set("X-Content-Type-Options","nosniff");headers.set("Content-Type",contentType(s.name));headers.set("Content-Length",Long.toString(length));
            boolean partial=exchange.getRequestHeaders().containsKey("Range");if(partial)headers.set("Content-Range","bytes "+start+"-"+end+"/"+s.size);
            if(exchange.getRequestMethod().equals("HEAD")||length==0){exchange.sendResponseHeaders(partial?206:200,-1);return;}
            long aligned=start-start%16;
            // Fetch whole ciphertext blocks and trim the decrypted response to the requested range.
            long fetchEnd=Math.min(s.size-1,end|15L);
            long fetchLength=fetchEnd-aligned+1;
            stage="upstream";
            int upstreamStatus=-1;
            for(int attempt=0;attempt<2;attempt++){
                if(cancelled(s)){exchange.sendResponseHeaders(410,-1);return;}
                upstream=context.open(ChunkWriterManager.genChunkUrl(s.url,s.size,aligned,fetchLength),false);
                // CDN range endpoints can close persistent connections after a short response.
                // A fresh connection avoids treating leftover/stale keep-alive bytes as headers.
                upstream.setRequestProperty("Connection","close");
                try{upstreamStatus=upstream.getResponseCode();}catch(IOException transport){if(attempt==1)throw transport;upstreamStatus=-1;}
                if(upstreamStatus==200||upstreamStatus==206)break;
                upstream.disconnect();
                if(attempt==1)break;
                if(cancelled(s)){exchange.sendResponseHeaders(410,-1);return;}
                if(upstreamStatus==403){s.url="megacrypter".equals(s.sourceKind)?HeadlessMegaCrypter.downloadUrl(s.source,s.passHash,s.noexpire,null):context.api(s.accountId).getMegaFileDownloadUrl(s.source);}
                else if(upstreamStatus!=-1&&upstreamStatus!=500&&upstreamStatus!=502&&upstreamStatus!=503)break;
            }
            if(upstreamStatus!=200&&upstreamStatus!=206){context.events.accept(map("type","streamError","stage",stage,"httpStatus",upstreamStatus));exchange.sendResponseHeaders(502,-1);return;}
            stage="decrypt";
            Cipher cipher=genDecrypter("AES","AES/CTR/NoPadding",initMEGALinkKey(s.key),forwardMEGALinkKeyIV(initMEGALinkKeyIV(s.key),aligned));
            if(cancelled(s)){exchange.sendResponseHeaders(410,-1);return;}
            exchange.sendResponseHeaders(partial?206:200,length);
            stage="body";
            try(InputStream in=upstream.getInputStream();OutputStream out=exchange.getResponseBody()) {
                long skip=start-aligned,remaining=length;byte[] buffer=new byte[65536];int n;
                while(remaining>0&&(n=in.read(buffer))!=-1){if(!sessions.containsKey(id))break;context.throttle(s.throttle,"download",n);byte[] decoded=cipher.update(buffer,0,n);int from=(int)Math.min(skip,decoded.length);skip-=from;int count=(int)Math.min(remaining,decoded.length-from);out.write(decoded,from,count);remaining-=count;}
            }
        }catch(Exception e){context.events.accept(map("type","streamError","stage",stage,"errorClass",e.getClass().getSimpleName()));try{exchange.sendResponseHeaders(502,-1);}catch(IOException ignored){}}
        finally{if(upstream!=null)upstream.disconnect();exchange.close();}
    }
    boolean cancelled(Session session){return session.throttle.stop||context.closed||Thread.currentThread().isInterrupted()||!sessions.containsKey(session.id);}
    static long[] parseRange(String value,long size){
        if(value==null)return new long[]{0,Math.max(0,size-1)};
        if(size==0||!value.matches("bytes=\\d*-\\d*"))return null;
        try{String[] parts=value.substring(6).split("-",-1);long start,end;
            if(parts[0].isEmpty()){long suffix=Long.parseLong(parts[1]);if(suffix<=0)return null;start=Math.max(0,size-suffix);end=size-1;}
            else{start=Long.parseLong(parts[0]);end=parts[1].isEmpty()?size-1:Math.min(Long.parseLong(parts[1]),size-1);}
            return start<0||start>=size||end<start?null:new long[]{start,end};
        }catch(NumberFormatException e){return null;}
    }
    static String contentType(String name){String lower=name.toLowerCase(Locale.ROOT);if(lower.endsWith(".mp4")||lower.endsWith(".m4v"))return "video/mp4";if(lower.endsWith(".webm"))return "video/webm";if(lower.endsWith(".mp3"))return "audio/mpeg";if(lower.endsWith(".m4a"))return "audio/mp4";if(lower.endsWith(".ogg"))return "audio/ogg";return "application/octet-stream";}
    @Override public void close(){for(Session s:sessions.values())s.throttle.stop=true;sessions.clear();if(server!=null)server.stop(0);if(workers!=null){workers.shutdownNow();try{if(!workers.awaitTermination(35,TimeUnit.SECONDS))throw new IllegalStateException("Streams did not quiesce");}catch(InterruptedException ex){Thread.currentThread().interrupt();throw new IllegalStateException("Stream shutdown interrupted",ex);}}}
}
