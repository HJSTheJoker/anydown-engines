package com.tonikelope.megabasterd.headless;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;
import com.tonikelope.megabasterd.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.nio.file.attribute.FileTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;
import static com.tonikelope.megabasterd.headless.EngineMain.*;
import static com.tonikelope.megabasterd.MiscTools.*;
import static com.tonikelope.megabasterd.CryptTools.*;

class UploadEngineTest {
    @TempDir Path root;
    HttpServer server; Path source;byte[] data,received;int[] publishedKey;
    AtomicInteger sessions=new AtomicInteger(),publications=new AtomicInteger(),folders=new AtomicInteger();
    volatile boolean expire,mutate;
    Map<String,String> remoteNodes=new HashMap<>();
    MegaAPI api;
    JsonNode params(Object...args){return JSON.valueToTree(map(args));}
    void fixture() throws Exception {
        data=new byte[412345];new Random(7764).nextBytes(data);received=new byte[data.length];source=root.resolve("source.bin");Files.write(source,data);
        server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),8);
        server.createContext("/upload/",exchange->{
            if(expire){expire=false;exchange.sendResponseHeaders(404,-1);exchange.close();return;}
            int offset=Integer.parseInt(exchange.getRequestURI().getPath().substring("/upload/".length()));byte[] body=exchange.getRequestBody().readAllBytes();System.arraycopy(body,0,received,offset,body.length);
            if(mutate){mutate=false;try{Files.write(source,new byte[]{1},StandardOpenOption.APPEND);}catch(IOException e){throw new UncheckedIOException(e);}}
            byte[] response=offset+body.length==data.length?new byte[27]:new byte[0];exchange.sendResponseHeaders(200,response.length==0?-1:response.length);if(response.length>0)exchange.getResponseBody().write(response);exchange.close();
        });server.start();
        api=new MegaAPI(){
            @Override public String getRoot_id(){return "root";}
            @Override public String initUploadFile(String path){sessions.incrementAndGet();return "http://127.0.0.1:"+server.getAddress().getPort()+"/upload";}
            @Override public int[] genUploadKey(){return new int[]{11,22,33,44,55,66};}
            @Override public String findOwnNodeHeadless(String parent,String name,int type,byte[] key){return remoteNodes.get(parent+":"+name+":"+Bin2UrlBASE64(key));}
            @Override public String createDirHeadless(String name,String parent,byte[] key){String id="folder-"+folders.incrementAndGet();remoteNodes.put(parent+":"+name+":"+Bin2UrlBASE64(key),id);return id;}
            @Override public HashMap<String,Object> finishUploadFileHeadless(String name,int[] uploadKey,int[] nodeKey,String handle,String parent){publications.incrementAndGet();publishedKey=nodeKey;remoteNodes.put(parent+":"+name+":"+Bin2UrlBASE64(i32a2bin(nodeKey)),"published");return new HashMap<>(map("f",List.of(map("h","published"))));}
        };
    }
    EngineContext context(Path profile) throws Exception {return new EngineContext(profile,event->{},()->api,id->api);}
    Transfer waitFor(EngineContext c,String id,String state) throws Exception {long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);while(System.nanoTime()<end){Transfer t=c.transfers.get(id);if(t!=null&&t.status.equals(state)&&!t.running)return t;if(t!=null&&t.status.equals("failed")&&!state.equals("failed"))fail(t.error);Thread.sleep(20);}fail("Expected "+state);return null;}
    @AfterEach void stop(){if(server!=null)server.stop(0);}
    @Test void uploadCiphertextMatchesSourceAndExpiredSessionCanRetry() throws Exception {
        fixture();expire=true;
        try(EngineContext c=context(root.resolve("profile"))){
            c.call("upload.start",params("id","upload","path",source.toString(),"accountId","synthetic","thumbnail",false));Transfer failed=waitFor(c,"upload","failed");assertNull(failed.uploadUrl);assertEquals(0,failed.completedBytes);
            c.call("transfer.retry",params("id","upload"));waitFor(c,"upload","completed");assertEquals(2,sessions.get());assertEquals(1,publications.get());
            String key=Bin2UrlBASE64(i32a2bin(publishedKey));assertArrayEquals(data,aes_ctr_decrypt_nopadding(received,initMEGALinkKey(key),initMEGALinkKeyIV(key)));MegaFileCrypto.verify(source,key);
            c.call("upload.start",params("id","upload","path",source.toString(),"accountId","synthetic"));assertEquals(1,publications.get());
        }
    }
    @Test void modifiedSourceNeverPublishes() throws Exception {
        fixture();mutate=true;
        try(EngineContext c=context(root.resolve("profile"))){c.call("upload.start",params("id","changing","path",source.toString(),"accountId","synthetic","thumbnail",false));Transfer failed=waitFor(c,"changing","failed");assertTrue(failed.error.contains("source changed"));assertEquals(0,publications.get());}
    }
    @Test void folderGroupsAreDurableAndDontCreateDuplicateRemoteFolders() throws Exception {
        fixture();Path folder=root.resolve("folder"),nested=folder.resolve("nested");Files.createDirectories(nested);Files.copy(source,nested.resolve("source.bin"));Path profile=root.resolve("group-profile");
        JsonNode start=params("id","group","path",folder.toString(),"accountId","synthetic","thumbnail",false,"rateLimitBytesPerSecond",0);
        List<String> ids;
        try(EngineContext c=context(profile)){c.call("upload.start",start);c.call("upload.start",start);assertEquals(2,folders.get());ids=new ArrayList<>(c.groups.get("group").children);for(String id:ids){c.call("transfer.pause",params("id",id));waitFor(c,id,"paused");}}
        try(EngineContext c=context(profile)){c.call("upload.start",start);assertEquals(2,folders.get());assertEquals(ids,c.groups.get("group").children);}
    }
}
