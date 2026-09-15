/* AnyDown headless integration. GPL-3.0. Metadata PBKDF2/AES scheme follows upstream MegaCrypterAPI. */
package com.tonikelope.megabasterd.headless;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.tonikelope.megabasterd.CryptTools;
import com.tonikelope.megabasterd.MiscTools;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import static com.tonikelope.megabasterd.headless.EngineMain.map;

/** Private provider metadata. Passwords are supplied through native challenges, never Swing. */
public final class HeadlessMegaCrypter {
    private HeadlessMegaCrypter() { }
    public static String[] metadata(String url,String password) throws Exception {return metadata(url,password,null);}
    public static String[] metadata(String url,String password,String reverse) throws Exception {
        JsonNode response=request(url,"info",null,null,reverse);String name=required(response,"name"),fileKey=required(response,"key"),path=response.path("path").isTextual()?response.path("path").asText():"";
        String size=response.path("size").asText();try{if(Long.parseLong(size)<0)throw new Exception();}catch(Exception ex){throw new RpcException(-32031,"MegaCrypter returned an invalid file size");}
        String expiry=null;if(response.path("expire").isTextual()){String value=response.path("expire").asText();int separator=value.indexOf('#');if(separator>=0 && separator<value.length()-1)expiry=value.substring(separator+1);}
        String passwordHash=null;
        if(response.path("pass").isTextual() && !response.path("pass").asText().isEmpty()) {
            if(password==null)throw passwordError();
            byte[] infoKey=null;
            try {
                String[] parts=response.path("pass").asText().split("#",-1);if(parts.length!=4)throw new Exception();
                int exponent=Integer.parseInt(parts[0]);if(exponent<1 || exponent>24)throw new RpcException(-32031,"Unsupported MegaCrypter password work factor");
                byte[] check=decode(parts[1]),salt=decode(parts[2]),iv=decode(parts[3]);if(salt.length<1 || salt.length>64 || iv.length!=16 || check.length>128)throw new Exception();
                infoKey=CryptTools.PBKDF2HMACSHA256(password,salt,1<<exponent,256);
                byte[] validation=CryptTools.aes_cbc_decrypt_pkcs7(check,infoKey,iv);boolean valid=MessageDigest.isEqual(infoKey,validation);Arrays.fill(validation,(byte)0);if(!valid)throw passwordError();
                fileKey=Base64.getUrlEncoder().withoutPadding().encodeToString(CryptTools.aes_cbc_decrypt_pkcs7(decode(fileKey),infoKey,iv));
                name=new String(CryptTools.aes_cbc_decrypt_pkcs7(decode(name),infoKey,iv),StandardCharsets.UTF_8);
                if(!path.isEmpty())path=new String(CryptTools.aes_cbc_decrypt_pkcs7(decode(path),infoKey,iv),StandardCharsets.UTF_8);
                passwordHash=Base64.getEncoder().encodeToString(infoKey);
            } catch(RpcException ex){throw ex;}
            catch(Exception ex){throw passwordError();}
            finally{if(infoKey!=null)Arrays.fill(infoKey,(byte)0);}
        }
        try{if(Base64.getUrlDecoder().decode(fileKey).length!=32)throw new Exception();}catch(Exception ex){throw new RpcException(-32031,"MegaCrypter returned an invalid MEGA file key");}
        return new String[]{safeName(path,name),size,fileKey,passwordHash,expiry};
    }
    public static String downloadUrl(String url,String passHash,String noexpire,String sid) throws Exception {return downloadUrl(url,passHash,noexpire,sid,null);}
    public static String downloadUrl(String url,String passHash,String noexpire,String sid,String reverse) throws Exception {
        JsonNode response=request(url,"dl",noexpire,sid,reverse);String result=required(response,"url");
        if(passHash!=null) {
            byte[] key=null,plain=null;
            try{key=decode(passHash);byte[] iv=decode(required(response,"pass"));if(key.length!=32 || iv.length!=16)throw new Exception();plain=CryptTools.aes_cbc_decrypt_pkcs7(decode(result),key,iv);result=new String(plain,StandardCharsets.UTF_8);}
            catch(Exception ex){throw passwordError();}
            finally{if(key!=null)Arrays.fill(key,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}
        }
        try{URI target=URI.create(result);if(!Arrays.asList("http","https").contains(target.getScheme()) || target.getHost()==null || target.getUserInfo()!=null || result.length()>65536)throw new Exception();}
        catch(Exception ex){throw new RpcException(-32031,"MegaCrypter returned an invalid download URL");}
        return result;
    }
    private static JsonNode request(String link,String method,String noexpire,String sid,String reverse) throws Exception {
        URL endpoint;
        try{URI uri=URI.create(link);if(!Arrays.asList("http","https").contains(uri.getScheme()) || uri.getHost()==null || uri.getUserInfo()!=null || link.length()>65536)throw new Exception();endpoint=new URI(uri.getScheme(),null,uri.getHost(),uri.getPort(),"/api",null,null).toURL();}
        catch(Exception ex){throw new RpcException(-32602,"Invalid MegaCrypter link");}
        Map<String,Object> body=map("m",method,"link",link);if(noexpire!=null)body.put("noexpire",noexpire);if(sid!=null)body.put("sid",sid);if(reverse!=null)body.put("reverse",reverse);
        try {
            byte[] bytes=ContainerHttp.post(endpoint,"application/json",EngineMain.JSON.writeValueAsBytes(body),Collections.emptyMap(),1024*1024);
            ObjectMapper json=new ObjectMapper().configure(JsonParser.Feature.ALLOW_SINGLE_QUOTES,true).configure(JsonParser.Feature.ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER,true);JsonNode response=json.readTree(bytes);
            if(response==null || !response.isObject())throw new RpcException(-32031,"Invalid MegaCrypter response");
            int error=response.path("error").asInt(0);if(error==25)throw passwordError();if(error!=0)throw new RpcException(-32031,"MegaCrypter provider error "+error);return response;
        } catch(RpcException ex){throw ex;}
        catch(Exception ex){throw new RpcException(-32031,"MegaCrypter response failed ("+ex.getClass().getSimpleName()+")");}
    }
    private static String safeName(String path,String name) throws RpcException {
        String cleaned=MiscTools.cleanFilename(name.replace('\\','/'));if(cleaned.isEmpty() || cleaned.equals("."))throw new RpcException(-32031,"MegaCrypter returned an invalid filename");
        List<String> segments=new ArrayList<>();for(String segment:path.replace('\\','/').split("/")){String safe=MiscTools.cleanFilename(segment);if(!safe.isEmpty() && !safe.equals("."))segments.add(safe);}segments.add(cleaned);return String.join("/",segments);
    }
    private static String required(JsonNode node,String name) throws RpcException {if(!node.path(name).isTextual() || node.path(name).asText().isEmpty())throw new RpcException(-32031,"MegaCrypter response is missing "+name);return node.path(name).asText();}
    private static byte[] decode(String value){return Base64.getDecoder().decode(value);}
    private static RpcException passwordError(){return new RpcException(-32030,"Enter the correct password for this MegaCrypter link");}
}
