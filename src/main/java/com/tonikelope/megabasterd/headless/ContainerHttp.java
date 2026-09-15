/* AnyDown headless integration. GPL-3.0. */
package com.tonikelope.megabasterd.headless;
import com.tonikelope.megabasterd.MainPanel;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounded, redacted transport for upstream container-provider protocols. */
final class ContainerHttp {
    static byte[] post(URL endpoint,String contentType,byte[] body,Map<String,String> headers,int limit) throws Exception {
        HttpURLConnection connection=null;
        try {
            if(!Arrays.asList("http","https").contains(endpoint.getProtocol()) || endpoint.getUserInfo()!=null)throw new RpcException(-32602,"Invalid container provider endpoint");
            connection=(HttpURLConnection)(MainPanel.isUse_proxy()?endpoint.openConnection(new Proxy(Proxy.Type.HTTP,new InetSocketAddress(MainPanel.getProxy_host(),MainPanel.getProxy_port()))):endpoint.openConnection());
            connection.setConnectTimeout(15000);connection.setReadTimeout(30000);connection.setInstanceFollowRedirects(false);connection.setUseCaches(false);connection.setRequestMethod("POST");connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type",contentType);connection.setRequestProperty("User-Agent",MainPanel.DEFAULT_USER_AGENT);
            for(Map.Entry<String,String> header:headers.entrySet())connection.setRequestProperty(header.getKey(),header.getValue());
            if(MainPanel.isUse_proxy() && MainPanel.getProxy_user()!=null && !MainPanel.getProxy_user().isEmpty())connection.setRequestProperty("Proxy-Authorization","Basic "+Base64.getEncoder().encodeToString((MainPanel.getProxy_user()+":"+MainPanel.getProxy_pass()).getBytes(StandardCharsets.UTF_8)));
            connection.setFixedLengthStreamingMode(body.length);try(OutputStream stream=connection.getOutputStream()){stream.write(body);}
            int status=connection.getResponseCode();if(status!=200)throw new RpcException(-32031,"Container provider returned HTTP "+status);
            try(InputStream input=connection.getInputStream();ByteArrayOutputStream output=new ByteArrayOutputStream()){
                byte[] buffer=new byte[8192];int count;while((count=input.read(buffer))!=-1){if(Thread.currentThread().isInterrupted())throw new InterruptedIOException();if(output.size()+count>limit)throw new RpcException(-32031,"Container provider response exceeds size limit");output.write(buffer,0,count);}return output.toByteArray();
            }
        } catch(RpcException ex){throw ex;}
        catch(Exception ex){throw new RpcException(-32031,"Container provider request failed ("+ex.getClass().getSimpleName()+")");}
        finally{if(connection!=null)connection.disconnect();}
    }
}
