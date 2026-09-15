package com.tonikelope.megabasterd.headless;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.tonikelope.megabasterd.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.tonikelope.megabasterd.headless.EngineMain.*;
class AccountFolderTest {
    @Test void decryptsOwnFolderNamesWithoutExposingKeys()throws Exception{
        byte[] master=new byte[16],key=new byte[16];Arrays.fill(key,(byte)77);
        String encrypted=MiscTools.Bin2UrlBASE64(CryptTools.aes_ecb_encrypt_nopadding(key,master));
        byte[] attributes=("MEGA"+JSON.writeValueAsString(map("n","Photos \"2026\" 🐈"))).getBytes(StandardCharsets.UTF_8);attributes=Arrays.copyOf(attributes,((attributes.length+15)/16)*16);
        String attr=MiscTools.Bin2UrlBASE64(CryptTools.aes_cbc_encrypt_nopadding(attributes,key,CryptTools.AES_ZERO_IV));
        List<Map<String,Object>> result=HeadlessFolderDecoder.decode(List.of(map("h","root","t",2),map("h","folder","p","root","t",1,"k","owner:"+encrypted,"a",attr),map("h","file","p","root","t",0,"k","owner:"+encrypted,"a",attr),map("h","inaccessible","p","root","t",1,"k","bad","a",attr)),master);
        assertEquals(2,result.size());assertEquals("Cloud Drive",result.get(0).get("name"));assertEquals("Photos \"2026\" 🐈",result.get(1).get("name"));assertEquals("root",result.get(1).get("parentId"));
        String json=JSON.writeValueAsString(result);assertFalse(json.contains(encrypted));assertFalse(json.contains(attr));assertFalse(json.contains("\"k\""));
    }
}
