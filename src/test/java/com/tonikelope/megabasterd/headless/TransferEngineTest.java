package com.tonikelope.megabasterd.headless;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;
import com.tonikelope.megabasterd.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static com.tonikelope.megabasterd.CryptTools.*;
import static com.tonikelope.megabasterd.MiscTools.*;
import static com.tonikelope.megabasterd.headless.EngineMain.*;

class TransferEngineTest {
    @TempDir Path temp;
    HttpServer server;
    byte[] plaintext,ciphertext;
    String fileKey;
    AtomicInteger requests=new AtomicInteger();
    boolean corrupt;
    String fakeLink="https://mega.nz/#!synthetic!synthetic";
    MegaAPI api;
    void fixture(int length) throws Exception {
        plaintext=new byte[length];new Random(872311).nextBytes(plaintext);
        Path original=temp.resolve("original");Files.write(original,plaintext);
        int[] key={11,22,33,44},nonce={55,66,0,0};
        int[] mac=MegaFileCrypto.mac(original,i32a2bin(key),i32a2bin(nonce));
        fileKey=Bin2UrlBASE64(i32a2bin(new int[]{key[0]^55,key[1]^66,key[2]^mac[0],key[3]^mac[1],55,66,mac[0],mac[1]}));
        ciphertext=aes_ctr_encrypt_nopadding(plaintext,i32a2bin(key),i32a2bin(nonce));
        server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),8);
        server.createContext("/file",exchange->{
            requests.incrementAndGet();String path=exchange.getRequestURI().getPath().substring("/file/".length());String[] range=path.split("-",-1);
            int start=Integer.parseInt(range[0]),end=range.length>1&&!range[1].isEmpty()?Integer.parseInt(range[1]):ciphertext.length-1;
            byte[] data=Arrays.copyOfRange(ciphertext,start,end+1);if(corrupt&&data.length>0)data[0]^=1;
            exchange.sendResponseHeaders(200,data.length);try(OutputStream out=exchange.getResponseBody()){out.write(data);}exchange.close();
        });server.start();
        api=new MegaAPI(){
            @Override public String[] getMegaFileMetadata(String link){return new String[]{"fixture.bin",Integer.toString(plaintext.length),fileKey};}
            @Override public String getMegaFileDownloadUrl(String link){return "http://127.0.0.1:"+server.getAddress().getPort()+"/file";}
        };
    }
    EngineContext context(Path profile) throws Exception {return new EngineContext(profile,event->{},()->api);}
    JsonNode params(Object...pairs){return JSON.valueToTree(map(pairs));}
    Transfer waitFor(EngineContext context,String id,String status) throws Exception {
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(20);
        while(System.nanoTime()<until){Transfer t=context.transfers.get(id);if(t!=null&&t.status.equals(status)&&!t.running)return t;if(t!=null&&t.status.equals("failed")&&!status.equals("failed"))fail(t.error);Thread.sleep(20);}
        fail("Transfer did not reach "+status);return null;
    }
    @AfterEach void stop(){if(server!=null)server.stop(0);}
    @Test void encryptedMultichunkDownloadIsPrivateIdempotentAndRateCoordinated() throws Exception {
        fixture(3_456_789);
        try(EngineContext context=context(temp.resolve("profile"))){
            Object resolved=context.call("transfer.resolve",params("url",fakeLink));String id=((Map<?,?>)resolved).get("resolutionId").toString();
            JsonNode start=params("id","fixture-transfer","resolutionId",id,"directory",temp.resolve("out").toString(),"rateLimitBytesPerSecond",0);
            context.call("download.start",start);Thread.sleep(300);assertEquals(0,requests.get(),"A zero coordinator allocation must hold payload before network fetch");
            context.call("download.start",start);assertEquals(1,context.transfers.size());
            context.call("transfer.rate",params("id","fixture-transfer","bytesPerSecond",null));
            Transfer completed=waitFor(context,"fixture-transfer","completed");assertArrayEquals(plaintext,Files.readAllBytes(Paths.get(completed.outputPath)));
            assertTrue(requests.get()>1,"Fixture crosses upstream chunk boundaries");
            String snapshot=JSON.writeValueAsString(context.call("engine.snapshot",params()));assertFalse(snapshot.contains(fakeLink));assertFalse(snapshot.contains(fileKey));
            assertTrue(Files.getPosixFilePermissions(context.profile.resolve("state.json")).toString().indexOf("GROUP")<0);
        }
    }
    @Test void emptyFilesPublishAndBadMacNeverPublishes() throws Exception {
        fixture(0);
        try(EngineContext context=context(temp.resolve("empty-profile"))){context.call("download.start",params("id","empty","url",fakeLink,"directory",temp.resolve("empty").toString()));Transfer t=waitFor(context,"empty","completed");assertEquals(0,Files.size(Paths.get(t.outputPath)));assertEquals(0,requests.get());}
        server.stop(0);fixture(4097);corrupt=true;
        try(EngineContext context=context(temp.resolve("corrupt-profile"))){context.call("download.start",params("id","bad","url",fakeLink,"directory",temp.resolve("bad").toString()));Transfer t=waitFor(context,"bad","failed");assertEquals("MEGA integrity verification failed",t.error);assertFalse(Files.exists(temp.resolve("bad/fixture.bin")));}
    }
    @Test void pauseRestartResumeAndOpaqueRangeStreaming() throws Exception {
        fixture(312345);
        Path profile=temp.resolve("resume-profile");String resolution;
        try(EngineContext context=context(profile)){
            resolution=((Map<?,?>)context.call("transfer.resolve",params("url",fakeLink))).get("resolutionId").toString();
            context.call("download.start",params("id","resume","resolutionId",resolution,"directory",temp.resolve("resume").toString(),"rateLimitBytesPerSecond",0));
            Thread.sleep(100);context.call("transfer.pause",params("id","resume"));waitFor(context,"resume","paused");
        }
        try(EngineContext context=context(profile)){
            assertTrue(context.resolutions.containsKey(resolution));assertEquals("paused",context.transfers.get("resume").status);
            context.call("transfer.rate",params("id","resume","bytesPerSecond",null));context.call("transfer.resume",params("id","resume"));waitFor(context,"resume","completed");
            Map<?,?> stream=(Map<?,?>)context.call("stream.start",params("resolutionId",resolution));String url=stream.get("url").toString();assertFalse(url.contains(fileKey));
            HttpURLConnection connection=(HttpURLConnection)new URL(url).openConnection();connection.setRequestProperty("Range","bytes=19-119");assertEquals(206,connection.getResponseCode());assertEquals("bytes 19-119/312345",connection.getHeaderField("Content-Range"));
            try(InputStream in=connection.getInputStream()){assertArrayEquals(Arrays.copyOfRange(plaintext,19,120),in.readAllBytes());}connection.disconnect();
            context.call("stream.stop",params("id",stream.get("id")));HttpURLConnection stopped=(HttpURLConnection)new URL(url).openConnection();assertEquals(404,stopped.getResponseCode());stopped.disconnect();
        }
    }
    @Test void thirdPartyProviderNeverReceivesSelectedAccountSession() throws Exception {
        fixture(4096);java.util.concurrent.atomic.AtomicReference<JsonNode> received=new java.util.concurrent.atomic.AtomicReference<>();
        String provider="http://127.0.0.1:"+server.getAddress().getPort()+"/protected";
        server.createContext("/api",exchange->{received.set(JSON.readTree(exchange.getRequestBody()));byte[] body=JSON.writeValueAsBytes(map("url","http://127.0.0.1:"+server.getAddress().getPort()+"/file"));exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);exchange.close();});
        MegaAPI privateAccount=new MegaAPI(){@Override public String getSid(){return "synthetic-private-session";}};
        try(EngineContext context=new EngineContext(temp.resolve("provider-profile"),event->{},()->api,id->privateAccount)){
            Transfer transfer=new Transfer();transfer.sourceKind="megacrypter";transfer.url=provider;
            context.runner.downloadUrl(transfer,privateAccount);assertFalse(received.get().has("sid"));
            LinkResolver.Resolution resolution=context.resolve(fakeLink);LinkResolver.Node node=resolution.children.get(0);node.sourceKind="megacrypter";node.url=provider;node.fileKey=fileKey;
            context.call("stream.start",params("resolutionId",resolution.resolutionId,"accountId","selected"));assertFalse(received.get().has("sid"));
        }
    }
    @Test void wwwMegaHostsRemainFirstParty() throws Exception {
        fixture(1234);
        try(EngineContext context=context(temp.resolve("www-profile"))){
            for(String host:List.of("www.mega.nz","www.mega.co.nz")){
                LinkResolver.Resolution resolved=context.resolve("https://"+host+"/#!synthetic!synthetic");
                assertEquals("mega",resolved.children.get(0).sourceKind);assertEquals("fixture.bin",resolved.name);
            }
        }
    }
    @Test void independentlyGeneratedMacGoldenAnswers() throws Exception {
        // Golden values computed independently with Python cryptography AES-ECB and
        // the MEGA chunk folding specification, never with MegaFileCrypto itself.
        int[] sizes={0,1,16,131073,3456789};String[] answers={"0000000000000000","747495ce6bddc030","7efc71f6e21ef669","7981396a19b02193","9b2f4f1d0a7f2fd6"};
        byte[] key=new byte[16],iv=new byte[16];for(int i=0;i<16;i++){key[i]=(byte)i;iv[i]=(byte)(16+i%8);}
        Path input=temp.resolve("golden");
        for(int i=0;i<sizes.length;i++){byte[] data=new byte[sizes[i]];for(int n=0;n<data.length;n++)data[n]=(byte)(n*73+19);Files.write(input,data);assertEquals(answers[i],java.util.HexFormat.of().formatHex(i32a2bin(MegaFileCrypto.mac(input,key,iv))));}
    }
    @Test void actualCompletedChunksSurviveRestartAndAreNotRedownloaded() throws Exception {
        fixture(3_456_789);Path profile=temp.resolve("partial-profile");long saved;int before;
        try(EngineContext context=context(profile)){
            context.settings.update(params("workerSlots",1));
            context.call("download.start",params("id","partial","url",fakeLink,"directory",temp.resolve("partial").toString(),"rateLimitBytesPerSecond",262144));
            long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while(context.transfers.get("partial").completedChunks.isEmpty()&&System.nanoTime()<until)Thread.sleep(20);
            context.call("transfer.pause",params("id","partial"));Transfer t=waitFor(context,"partial","paused");saved=t.completedBytes;assertTrue(saved>0&&saved<t.totalBytes);before=requests.get();
        }
        try(EngineContext context=context(profile)){
            assertEquals(saved,context.transfers.get("partial").completedBytes);context.call("transfer.rate",params("id","partial","bytesPerSecond",null));context.call("transfer.resume",params("id","partial"));Transfer t=waitFor(context,"partial","completed");assertArrayEquals(plaintext,Files.readAllBytes(Paths.get(t.outputPath)));
            assertTrue(requests.get()-before<t.completedChunks.size(),"Completed chunks must not be downloaded again");
        }
    }
    @Test void rangeValidationRejectsAmbiguityAndHandlesSuffix(){
        assertArrayEquals(new long[]{90,99},StreamSessions.parseRange("bytes=-10",100));assertArrayEquals(new long[]{0,99},StreamSessions.parseRange("bytes=0-200",100));
        assertNull(StreamSessions.parseRange("bytes=100-",100));assertNull(StreamSessions.parseRange("bytes=0-2,4-6",100));assertNull(StreamSessions.parseRange("bytes=-",100));assertNull(StreamSessions.parseRange("bytes=-0",100));
    }
}
