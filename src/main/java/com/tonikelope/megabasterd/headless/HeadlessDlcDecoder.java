/* AnyDown headless integration. GPL-3.0. DLC AES framing follows upstream CryptTools.decryptDLC. */
package com.tonikelope.megabasterd.headless;

import com.tonikelope.megabasterd.CryptTools;
import com.tonikelope.megabasterd.MiscTools;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

public final class HeadlessDlcDecoder {
    private static final int LIMIT=8*1024*1024;
    private static final String SERVICE="http://service.jdownloader.org/dlcrypt/service.php",REVISION="34065",MASTER="447E787351E60E2C6A96B3964BE0C9BD";
    private HeadlessDlcDecoder() { }
    public static Set<String> decrypt(String data) throws Exception {return decrypt(data,URI.create(SERVICE).toURL());}
    static Set<String> decrypt(String data,URL service) throws Exception {
        try {
            if(data==null || data.length()<89 || data.length()>LIMIT*2)throw new RpcException(-32602,"Invalid or oversized DLC container");
            data=data.trim();if(data.length()<89)throw new RpcException(-32602,"Invalid DLC container");
            String id=data.substring(data.length()-88),encrypted=data.substring(0,data.length()-88).trim();byte[] ciphertext=decode(encrypted);
            if(ciphertext.length<16 || ciphertext.length%16!=0 || ciphertext.length>LIMIT || !id.matches("[A-Za-z0-9+/=_-]{88}"))throw new RpcException(-32602,"Invalid DLC framing");
            String body="destType=jdtc6&b=JD&srcType=dlc&data="+URLEncoder.encode(id,StandardCharsets.UTF_8)+"&v="+REVISION;
            String reply=new String(ContainerHttp.post(service,"application/x-www-form-urlencoded; charset=UTF-8",body.getBytes(StandardCharsets.UTF_8),Map.of("rev",REVISION),65536),StandardCharsets.UTF_8);
            Matcher keyMatch=Pattern.compile("<\\s*rc\\s*>([^<]+)<\\s*/\\s*rc\\s*>",Pattern.DOTALL).matcher(reply);if(!keyMatch.find())throw new RpcException(-32031,"DLC provider did not return a key");
            byte[] encryptedKey=decode(keyMatch.group(1));if(encryptedKey.length<16 || encryptedKey.length>256 || encryptedKey.length%16!=0)throw new RpcException(-32031,"Invalid DLC provider key");
            byte[] keyText=CryptTools.aes_ecb_decrypt_nopadding(encryptedKey,MiscTools.hex2bin(MASTER));byte[] key=decode(new String(keyText,StandardCharsets.UTF_8).trim());Arrays.fill(keyText,(byte)0);if(key.length!=16)throw new RpcException(-32031,"Invalid DLC decryption key");
            byte[] decrypted=null,xmlBytes=null;
            try {
                decrypted=CryptTools.aes_cbc_decrypt_nopadding(ciphertext,key,key);xmlBytes=decode(new String(decrypted,StandardCharsets.UTF_8).trim());if(xmlBytes.length>LIMIT)throw new RpcException(-32602,"DLC contents exceed size limit");
                String xml=new String(xmlBytes,StandardCharsets.UTF_8);Matcher files=Pattern.compile("<\\s*file\\s*>(.*?)<\\s*/\\s*file\\s*>",Pattern.DOTALL).matcher(xml);Set<String> links=new LinkedHashSet<>();
                while(files.find()) {Matcher urls=Pattern.compile("<\\s*url\\s*>([^<]+)<\\s*/\\s*url\\s*>",Pattern.DOTALL).matcher(files.group(1));while(urls.find()) {
                    String link=new String(decode(urls.group(1)),StandardCharsets.UTF_8).trim();URI uri=URI.create(link);
                    if(link.length()>65536 || !Arrays.asList("http","https").contains(uri.getScheme()) || uri.getHost()==null || uri.getUserInfo()!=null)throw new RpcException(-32602,"DLC contains an invalid download link");
                    if(links.size()>=10000)throw new RpcException(-32602,"DLC contains too many links");links.add(link);
                }}
                if(links.isEmpty())throw new RpcException(-32602,"DLC contains no download links");return links;
            } finally {Arrays.fill(key,(byte)0);if(decrypted!=null)Arrays.fill(decrypted,(byte)0);if(xmlBytes!=null)Arrays.fill(xmlBytes,(byte)0);}
        } catch(RpcException ex){throw ex;}
        catch(Exception ex){throw new RpcException(-32031,"DLC resolution failed ("+ex.getClass().getSimpleName()+")");}
    }
    private static byte[] decode(String value){return Base64.getDecoder().decode(value.replaceAll("[\\r\\n\\t ]", ""));}
}
