package com.tonikelope.megabasterd.headless;

import com.tonikelope.megabasterd.CryptTools;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.tonikelope.megabasterd.headless.EngineMain.*;

class HeadlessElcDecoderTest {
    private String container(String endpoint,byte[] key,byte[] iv) throws Exception {
        String links="#!filehandle!syntheticKey";byte[] text=links.getBytes(StandardCharsets.UTF_8);byte[] padded=Arrays.copyOf(text,((text.length+15)/16)*16);
        byte[] ciphertext=CryptTools.aes_cbc_encrypt_nopadding(padded,key,iv),url=endpoint.getBytes(StandardCharsets.UTF_8),token="token&with=spaces +".getBytes(StandardCharsets.UTF_8);
        ByteBuffer encoded=ByteBuffer.allocate(1+4+ciphertext.length+2+url.length+2+token.length).order(ByteOrder.LITTLE_ENDIAN);encoded.put((byte)185).putInt(ciphertext.length).put(ciphertext).putShort((short)url.length).put(url).putShort((short)token.length).put(token);
        return "mega://elc?"+Base64.getUrlEncoder().withoutPadding().encodeToString(encoded.array());
    }
    @Test void decodesUpstreamContainerWithHostBoundCredentialsAndEncodedForm() throws Exception {
        byte[] key=new byte[16],iv=new byte[16];Arrays.fill(key,(byte)4);Arrays.fill(iv,0,8,(byte)6);byte[] material=new byte[24];System.arraycopy(key,0,material,0,16);System.arraycopy(iv,0,material,16,8);
        AtomicReference<String> received=new AtomicReference<>();HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/decrypt",exchange->{received.set(new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));byte[] response=JSON.writeValueAsBytes(map("d",Base64.getEncoder().encodeToString(material)));exchange.sendResponseHeaders(200,response.length);exchange.getResponseBody().write(response);exchange.close();});server.start();
        try {
            String link=container("http://127.0.0.1:"+server.getAddress().getPort()+"/decrypt",key,iv);assertEquals("127.0.0.1",HeadlessElcDecoder.host(link));
            Set<String> decoded=HeadlessElcDecoder.decrypt(link,JSON.valueToTree(map("host","127.0.0.1","user","user&value","apikey","fake+secret")));
            assertEquals(Set.of("https://mega.nz/#!filehandle!syntheticKey"),decoded);assertTrue(received.get().contains("USER=user%26value"));assertTrue(received.get().contains("APIKEY=fake%2Bsecret"));
            assertThrows(RpcException.class,()->HeadlessElcDecoder.decrypt(link,JSON.valueToTree(map("host","different.invalid","user","x","apikey","y"))));
        } finally {server.stop(0);}
    }
    @Test void rejectsMalformedContainersBeforeNetworkAccess() {
        assertThrows(RpcException.class,()->HeadlessElcDecoder.host("mega://elc?AA"));
        assertThrows(RpcException.class,()->HeadlessElcDecoder.host("mega://elc?"+Base64.getUrlEncoder().encodeToString(new byte[]{(byte)185,-1,-1,-1,127})));
    }
}
