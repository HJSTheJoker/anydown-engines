package com.tonikelope.megabasterd.headless;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;
import com.tonikelope.megabasterd.CryptTools;
import com.tonikelope.megabasterd.MiscTools;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.tonikelope.megabasterd.headless.EngineMain.*;

class HeadlessContainersTest {
    private static String b64(byte[] data){return Base64.getEncoder().encodeToString(data);}
    private static byte[] utf8(String value){return value.getBytes(StandardCharsets.UTF_8);}
    private static byte[] padded(byte[] value){return Arrays.copyOf(value,((value.length+15)/16)*16);}
    @Test void nativePasswordChallengesDecryptUpstreamMegacrypterMetadataAndUrl() throws Exception {
        byte[] salt=new byte[16],iv=new byte[16],fileKey=new byte[32];Arrays.fill(salt,(byte)6);Arrays.fill(iv,(byte)2);Arrays.fill(fileKey,(byte)7);
        byte[] infoKey=CryptTools.PBKDF2HMACSHA256("fixture-password",salt,256,256);
        String pass="8#"+b64(CryptTools.aes_cbc_encrypt_pkcs7(infoKey,infoKey,iv))+"#"+b64(salt)+"#"+b64(iv);
        Map<String,Object> encrypted=map("name",b64(CryptTools.aes_cbc_encrypt_pkcs7(utf8("movie.mp4"),infoKey,iv)),"path",b64(CryptTools.aes_cbc_encrypt_pkcs7(utf8("nested/"),infoKey,iv)),"size",12345678901L,"key",b64(CryptTools.aes_cbc_encrypt_pkcs7(fileKey,infoKey,iv)),"pass",pass,"expire","999#expiry-secret");
        String expectedUrl="https://download.example.invalid/file?token=synthetic-private";Map<String,Object> download=map("url",b64(CryptTools.aes_cbc_encrypt_pkcs7(utf8(expectedUrl),infoKey,iv)),"pass",b64(iv));
        AtomicReference<JsonNode> last=new AtomicReference<>();AtomicInteger error=new AtomicInteger();HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/api",exchange->{JsonNode request=JSON.readTree(exchange.getRequestBody());last.set(request);Object body=error.get()!=0?map("error",error.get()):request.path("m").asText().equals("info")?encrypted:download;byte[] response=JSON.writeValueAsBytes(body);exchange.sendResponseHeaders(200,response.length);exchange.getResponseBody().write(response);exchange.close();});server.start();
        try {
            String url="http://127.0.0.1:"+server.getAddress().getPort()+"/protected";
            assertEquals(-32030,assertThrows(RpcException.class,()->HeadlessMegaCrypter.metadata(url,null)).code);
            assertEquals(-32030,assertThrows(RpcException.class,()->HeadlessMegaCrypter.metadata(url,"wrong-password")).code);
            String[] metadata=HeadlessMegaCrypter.metadata(url,"fixture-password","configured-reverse");assertEquals("nested/movie.mp4",metadata[0]);assertEquals("12345678901",metadata[1]);assertArrayEquals(fileKey,Base64.getUrlDecoder().decode(metadata[2]));assertEquals(b64(infoKey),metadata[3]);assertEquals("expiry-secret",metadata[4]);assertEquals("configured-reverse",last.get().path("reverse").asText());
            assertEquals(expectedUrl,HeadlessMegaCrypter.downloadUrl(url,metadata[3],metadata[4],"synthetic-session"));assertEquals("expiry-secret",last.get().path("noexpire").asText());assertEquals("synthetic-session",last.get().path("sid").asText());
            // Decoded DLC URL lists share the exact native challenge path with pasted links.
            java.nio.file.Path profile=java.nio.file.Files.createTempDirectory("headless-link-challenge-");
            try(EngineContext context=new EngineContext(profile,event->{})){
                JsonNode challenged=JSON.valueToTree(context.resolveOrChallenge(List.of(url)));
                String challengeId=challenged.path("challenge").path("id").asText();assertFalse(challengeId.isEmpty());
                JsonNode resolved=JSON.valueToTree(context.call("challenge.respond",JSON.valueToTree(map("id",challengeId,"value","fixture-password"))));
                assertFalse(resolved.path("resolutionId").asText().isEmpty());assertEquals(1,resolved.path("children").size());assertFalse(resolved.toString().contains(url));assertTrue(context.linkChallenges.isEmpty());
            }
            error.set(25);assertEquals(-32030,assertThrows(RpcException.class,()->HeadlessMegaCrypter.metadata(url,"fixture-password")).code);
            error.set(-6);RpcException failure=assertThrows(RpcException.class,()->HeadlessMegaCrypter.metadata(url,null));assertEquals(-32031,failure.code);assertFalse(failure.getMessage().contains(url));
        } finally{server.stop(0);}
    }
    @Test void unprotectedMegacrypterMetadataSanitizesPathsAndRejectsExternalSchemes() throws Exception {
        byte[] key=new byte[32];HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/api",exchange->{JsonNode request=JSON.readTree(exchange.getRequestBody());Object body=request.path("m").asText().equals("info")?map("name","safe.txt","path","../../nested/","size",0,"key",Base64.getUrlEncoder().withoutPadding().encodeToString(key),"pass",false,"expire",false):map("url","file:///sensitive");byte[] response=JSON.writeValueAsBytes(body);exchange.sendResponseHeaders(200,response.length);exchange.getResponseBody().write(response);exchange.close();});server.start();
        try{String url="http://127.0.0.1:"+server.getAddress().getPort()+"/public";String[] info=HeadlessMegaCrypter.metadata(url,null);assertEquals("nested/safe.txt",info[0]);assertEquals("0",info[1]);assertNull(info[3]);assertNull(info[4]);assertThrows(RpcException.class,()->HeadlessMegaCrypter.downloadUrl(url,null,null,null));assertThrows(RpcException.class,()->HeadlessMegaCrypter.metadata("file:///etc/passwd",null));}finally{server.stop(0);}
    }
    @Test void decryptsUpstreamDlcCipherChainWithoutDialogs() throws Exception {
        byte[] key=new byte[16];Arrays.fill(key,(byte)9);String expected="https://mega.nz/#!handle!synthetic-key";
        String xml="<dlc><content><file><url>"+b64(utf8(expected))+"</url></file></content></dlc>";
        byte[] encrypted=CryptTools.aes_cbc_encrypt_nopadding(padded(utf8(b64(utf8(xml)))),key,key);
        byte[] encryptedKey=CryptTools.aes_ecb_encrypt_nopadding(padded(utf8(b64(key))),MiscTools.hex2bin("447E787351E60E2C6A96B3964BE0C9BD"));
        String data=b64(encrypted)+"+".repeat(88);AtomicReference<String> body=new AtomicReference<>();HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/dlc",exchange->{body.set(new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));byte[] response=utf8("<response><rc>"+b64(encryptedKey)+"</rc></response>");exchange.sendResponseHeaders(200,response.length);exchange.getResponseBody().write(response);exchange.close();});server.start();
        try {URL endpoint=URI.create("http://127.0.0.1:"+server.getAddress().getPort()+"/dlc").toURL();assertEquals(Set.of(expected),HeadlessDlcDecoder.decrypt(data+"\n",endpoint));assertTrue(body.get().contains("data=%2B%2B"));assertTrue(body.get().contains("v=34065"));
            assertThrows(RpcException.class,()->HeadlessDlcDecoder.decrypt("tiny",endpoint));assertThrows(RpcException.class,()->HeadlessDlcDecoder.decrypt("not-base64"+"A".repeat(88),endpoint));
        } finally{server.stop(0);}
    }
    @Test void containerRequestsDoNotFollowRedirects() throws Exception {
        AtomicInteger followed=new AtomicInteger();HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/api",exchange->{exchange.getRequestBody().close();exchange.getResponseHeaders().set("Location","/redirect");exchange.sendResponseHeaders(302,-1);exchange.close();});server.createContext("/redirect",exchange->{followed.incrementAndGet();exchange.sendResponseHeaders(200,-1);exchange.close();});server.start();
        try{RpcException error=assertThrows(RpcException.class,()->HeadlessMegaCrypter.metadata("http://127.0.0.1:"+server.getAddress().getPort()+"/link",null));assertEquals(-32031,error.code);assertEquals(0,followed.get());}finally{server.stop(0);}
    }
}
