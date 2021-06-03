package io.springboot.oauth2.web.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;

@Slf4j
@Controller
@RequestMapping("")
public class OauthController {


    private static final String ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token";

    private static final String USER_URL = "https://api.github.com/user";

    @Autowired
    private RestTemplate restTemplate;

    @Value("${oauth.github.app-id}")
    private String appId;

    @Value("${oauth.github.app-secret}")
    private String appSecret;

    /**
     * Github回调
     *
     * @param request
     * @param code
     * @param state
     * @return
     */
    @GetMapping("/github/login")
    public ModelAndView github(HttpServletRequest request, @RequestParam("code") String code,
                               @RequestParam(value = "state", required = false) String state) {

        log.info("授权码 :code={}, state={}", code, state);

        /**
         * 使用code获取accessToken
         */
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        httpHeaders.set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);

        MultiValueMap<String, Object> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", this.appId);
        requestBody.add("client_secret", this.appSecret);
        requestBody.add("code", code);

        HttpEntity<MultiValueMap<String, Object>> httpEntity = new HttpEntity<>(requestBody, httpHeaders);

        ResponseEntity<JSONObject> responseEntity = this.restTemplate.postForEntity(ACCESS_TOKEN_URL, httpEntity,
                JSONObject.class);

        JSONObject jsonObject = responseEntity.getBody();
        String accessToken = jsonObject.getString("access_token");
        String scope = jsonObject.getString("scope");
        String tokenType = jsonObject.getString("token_type");

        log.info("accessToken={}, scope={}, tokenType={}", accessToken, scope, tokenType);

        /**
         * 通过accessToken获取用户信息
         */
        httpHeaders = new HttpHeaders();
        httpHeaders.set(HttpHeaders.AUTHORIZATION, "token " + accessToken);
        httpHeaders.set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);

        responseEntity = this.restTemplate.exchange(USER_URL, HttpMethod.GET, new HttpEntity<Void>(null, httpHeaders),
                JSONObject.class);
        jsonObject = responseEntity.getBody();

        log.info("user={}", jsonObject);

        /**
         * TODO 从用户信息中获取到id，匹配本地数据库关联的系统用户。从而完成登录逻辑。
         */
        HttpSession session = request.getSession();
        session.setAttribute("user", JSON.toJSONString(jsonObject, SerializerFeature.PrettyFormat));
        return new ModelAndView("redirect:/index");
    }
}
