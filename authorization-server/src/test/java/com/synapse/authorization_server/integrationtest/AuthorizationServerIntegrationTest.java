package com.synapse.authorization_server.integrationtest;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * 실제 애플리케이션의 전체 컨텍스트를 로드하여 통합 테스트를 진행합니다.
 * 이 테스트는 Authorization Server가 클라이언트의 요청에 대해 정상적으로 토큰을 발급하는지 검증합니다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthorizationServerIntegrationTest {
    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("토큰 발급 성공: 올바른 클라이언트 정보로 요청 시, Access Token을 성공적으로 발급한다")
    void issueToken_success_withValidClient() throws Exception {
        // given
        String clientId = "test-client";
        String clientSecret = "test-secret";

        // 요청 바디(form-data) 구성
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");
        params.add("scope", "api.internal test.scope");

        // when
        ResultActions actions = mockMvc.perform(post("/oauth2/token")
                .params(params)
                .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes())));

        // then
        actions
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.scope").value("api.internal test.scope"))
                .andExpect(jsonPath("$.expires_in").isNumber());
    }

    @Test
    @DisplayName("토큰 발급 실패: 잘못된 Client Secret으로 요청 시, 401 Unauthorized를 응답한다")
    void issueToken_fail_withInvalidClientSecret() throws Exception {
        // given
        String clientId = "test-client";
        String wrongClientSecret = "wrong-secret"; // 잘못된 시크릿

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");

        // when
        ResultActions actions = mockMvc.perform(post("/oauth2/token")
                .params(params)
                .header(HttpHeaders.AUTHORIZATION, "Basic "
                        + Base64.getEncoder().encodeToString((clientId + ":" + wrongClientSecret).getBytes())));

        // then
        actions
                .andDo(print())
                .andExpect(status().isUnauthorized()) // 401 Unauthorized 상태 코드 확인
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    @DisplayName("토큰 발급 실패: 허용되지 않은 Scope을 요청 시, 400 Bad Request를 응답한다")
    void issueToken_fail_withInvalidScope() throws Exception {
        // given
        String clientId = "test-client";
        String clientSecret = "test-secret";

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");
        params.add("scope", "api.unauthorized"); // 등록되지 않은 scope

        // when
        ResultActions actions = mockMvc.perform(post("/oauth2/token")
                .params(params)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes())));

        // then
        actions
                .andDo(print())
                .andExpect(status().isBadRequest()) // 400 Bad Request 상태 코드 확인
                .andExpect(jsonPath("$.error").value("invalid_scope"));
    }
}
