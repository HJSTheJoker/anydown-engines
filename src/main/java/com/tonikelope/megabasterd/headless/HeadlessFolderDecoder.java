package com.tonikelope.megabasterd.headless;
import com.tonikelope.megabasterd.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import static com.tonikelope.megabasterd.headless.EngineMain.*;
/** Own-account destination folders only. Decryption keys never enter the returned tree. */
public final class HeadlessFolderDecoder {
    private HeadlessFolderDecoder(){}
    public static List<Map<String,Object>> decode(List<?> nodes,byte[] masterKey){
        List<Map<String,Object>> folders=new ArrayList<>();
        for(Object value:nodes){
            if(!(value instanceof Map))continue;Map<?,?> node=(Map<?,?>)value;
            if(!(node.get("t") instanceof Number)||!(node.get("h") instanceof String))continue;int type=((Number)node.get("t")).intValue();
            if(type==2){folders.add(map("id",node.get("h"),"name","Cloud Drive","parentId",null));continue;}
            if(type!=1||!(node.get("k") instanceof String)||!(node.get("a") instanceof String))continue;
            for(String segment:node.get("k").toString().split("/")){
                try{
                    byte[] key=CryptTools.aes_ecb_decrypt_nopadding(MiscTools.UrlBASE642Bin(segment.substring(segment.lastIndexOf(':')+1)),masterKey);
                    if(key.length!=16)continue;
                    byte[] bytes=CryptTools.aes_cbc_decrypt_nopadding(MiscTools.UrlBASE642Bin(node.get("a").toString()),key,CryptTools.AES_ZERO_IV);
                    String plain=new String(bytes,StandardCharsets.UTF_8).trim();if(!plain.startsWith("MEGA"))continue;
                    String name=JSON.readTree(plain.substring(4)).path("n").asText("");if(name.isEmpty())continue;
                    folders.add(map("id",node.get("h"),"name",name,"parentId",node.get("p")));break;
                }catch(Exception ignored){}
            }
        }
        folders.sort(Comparator.comparing((Map<String,Object> node)->node.get("parentId")!=null).thenComparing(node->node.get("name").toString(),String.CASE_INSENSITIVE_ORDER));
        return folders;
    }
}
