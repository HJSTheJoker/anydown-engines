/* AnyDown headless integration. GPL-3.0. ELC framing and AES scheme follow upstream CryptTools.decryptELC. */
package com.tonikelope.megabasterd.headless;

import com.fasterxml.jackson.databind.JsonNode;
import com.tonikelope.megabasterd.CryptTools;
import com.tonikelope.megabasterd.MainPanel;
import com.tonikelope.megabasterd.MiscTools;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.GZIPInputStream;

/** ELC resolution with caller-provided private credentials and no UI dependencies. */
public final class HeadlessElcDecoder {
    private static final int LIMIT=8*1024*1024;
    private record Container(byte[] links,URL endpoint,String token) { }
    private HeadlessElcDecoder() { }
    public static String host(String link) throws Exception {return parse(link).endpoint.getHost();}
    public static Set<String> decrypt(String link,JsonNode credentials) throws Exception {
        Container container=parse(link);
        if(!credentials.path("host").asText().equalsIgnoreCase(container.endpoint.getHost()) || !credentials.path("user").isTextual() || !credentials.path("apikey").isTextual())throw new RpcException(-32602,"ELC credentials do not match this link provider");
        HttpURLConnection connection=null;
        try {
            if(MainPanel.isUse_proxy())connection=(HttpURLConnection)container.endpoint.openConnection(new Proxy(Proxy.Type.HTTP,new InetSocketAddress(MainPanel.getProxy_host(),MainPanel.getProxy_port())));
            else connection=(HttpURLConnection)container.endpoint.openConnection();
            connection.setConnectTimeout(15000);connection.setReadTimeout(30000);connection.setInstanceFollowRedirects(false);connection.setRequestMethod("POST");connection.setDoOutput(true);connection.setUseCaches(false);
            connection.setRequestProperty("User-Agent",MainPanel.DEFAULT_USER_AGENT);connection.setRequestProperty("Content-Type","application/x-www-form-urlencoded; charset=UTF-8");
            if(MainPanel.isUse_proxy() && MainPanel.getProxy_user()!=null && !MainPanel.getProxy_user().isEmpty())connection.setRequestProperty("Proxy-Authorization","Basic "+Base64.getEncoder().encodeToString((MainPanel.getProxy_user()+":"+MainPanel.getProxy_pass()).getBytes(StandardCharsets.UTF_8)));
            String body="OPERATION_TYPE=D&DATA="+encode(container.token)+"&USER="+encode(credentials.path("user").asText())+"&APIKEY="+encode(credentials.path("apikey").asText());
            byte[] request=body.getBytes(StandardCharsets.UTF_8);connection.setFixedLengthStreamingMode(request.length);try(OutputStream output=connection.getOutputStream()){output.write(request);}
            int status=connection.getResponseCode();if(status!=200)throw new RpcException(-32020,"ELC provider rejected the request (HTTP "+status+")");
            JsonNode response;try(InputStream input=connection.getInputStream()){response=EngineMain.JSON.readTree(bounded(input,65536));}
            if(!response.path("d").isTextual())throw new RpcException(-32020,"ELC provider did not return a decryption key");
            byte[] material=Base64.getDecoder().decode(response.path("d").asText());if(material.length<24 || material.length>64)throw new RpcException(-32020,"Invalid ELC key response");
            byte[] key=Arrays.copyOf(material,16),iv=new byte[16],plain=null;System.arraycopy(material,16,iv,0,8);
            try {
                plain=CryptTools.aes_cbc_decrypt_nopadding(container.links,key,iv);String[] parts=new String(plain,StandardCharsets.UTF_8).trim().split("\\|");Set<String> links=new LinkedHashSet<>();
                for(String part:parts){if(!part.matches("(?:#(?:F)?!|file/|folder/)[A-Za-z0-9_!#/-]+"))throw new RpcException(-32020,"ELC provider returned an invalid MEGA link");links.add("https://mega.nz/"+part);}
                return links;
            } finally {Arrays.fill(material,(byte)0);Arrays.fill(key,(byte)0);Arrays.fill(iv,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}
        } catch(RpcException ex){throw ex;}
        catch(Exception ex){throw new RpcException(-32020,"ELC resolution failed ("+ex.getClass().getSimpleName()+")");}
        finally{if(connection!=null)connection.disconnect();}
    }
    private static Container parse(String link) throws Exception {
        try {
            if(link==null || !link.startsWith("mega://elc?") || link.length()>LIMIT*2)throw new Exception();
            byte[] encoded=MiscTools.UrlBASE642Bin(link.substring("mega://elc?".length()));if(encoded.length<2)throw new Exception();
            int marker=Byte.toUnsignedInt(encoded[0]);if(marker!=112 && marker!=185)throw new Exception();
            byte[] bytes=Arrays.copyOfRange(encoded,1,encoded.length);
            if(marker==112){try(InputStream gzip=new GZIPInputStream(new ByteArrayInputStream(bytes))){bytes=bounded(gzip,LIMIT);}}
            if(bytes.length>LIMIT)throw new Exception();ByteBuffer buffer=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            int length=buffer.getInt();if(length<16 || length%16!=0 || length>buffer.remaining()-4)throw new Exception();byte[] links=new byte[length];buffer.get(links);
            int urlLength=Short.toUnsignedInt(buffer.getShort());if(urlLength<1 || urlLength>buffer.remaining()-2)throw new Exception();byte[] urlBytes=new byte[urlLength];buffer.get(urlBytes);
            int tokenLength=Short.toUnsignedInt(buffer.getShort());if(tokenLength<1 || tokenLength>buffer.remaining())throw new Exception();byte[] token=new byte[tokenLength];buffer.get(token);if(buffer.hasRemaining())throw new Exception();
            URL url=URI.create(new String(urlBytes,StandardCharsets.UTF_8).trim()).toURL();if(!Arrays.asList("http","https").contains(url.getProtocol()) || url.getHost().isEmpty() || url.getUserInfo()!=null || url.getRef()!=null)throw new Exception();
            return new Container(links,url,new String(token,StandardCharsets.UTF_8));
        } catch(Exception ex){throw new RpcException(-32602,"Invalid or oversized ELC container");}
    }
    private static String encode(String value){return URLEncoder.encode(value,StandardCharsets.UTF_8);}
    private static byte[] bounded(InputStream input,int limit) throws IOException {
        ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int count;
        while((count=input.read(buffer))!=-1){if(output.size()+count>limit)throw new IOException("ELC input exceeds limit");output.write(buffer,0,count);}return output.toByteArray();
    }
}
