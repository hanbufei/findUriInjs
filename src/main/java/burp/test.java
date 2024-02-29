package burp;

import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class test {
    public static void main(String[] args){
        Pattern p1 = Pattern.compile("(^GET /.*\\.js)|(^GET /.*\\.htm)");
        Matcher m1 = p1.matcher("GET /dsadsa/dsad/1.html?dsad=123");
        if (m1.find()){System.out.println(m1.group(0));}}

//        HashSet<String> link = new HashSet<>();
//        link.add("1");
//        link.add("1");
//        link.add("2");
//        link.add("2");
//        String links = new String();
//        for (String item : link){
//            links = links + "\n" + item;
//        }
//        System.out.println(links);
//    }
}
