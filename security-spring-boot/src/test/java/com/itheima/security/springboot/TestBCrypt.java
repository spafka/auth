package com.itheima.security.springboot;



import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Administrator
 * @version 1.0
 **/
@RunWith(SpringRunner.class)
public class TestBCrypt {

    @Test
    public void testBCrypt(){

        Pattern compile = Pattern.compile("[a-z]{8,16}");
        Matcher aaaaaaaa = compile.matcher("aaaaaaaa");
        aaaaaaaa.matches();

        System.out.println();
    }
}
