package com.smartdrive.authservice.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequiredArgsConstructor
@Slf4j
public class OAuth2ConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    @GetMapping("/oauth2/consent")
    public String consent(Principal principal, Model model,
                        @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                        @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                        @RequestParam(OAuth2ParameterNames.STATE) String state) {
        
        log.info("🔐 OAuth2 consent request for client: {}, scope: {}, state: {}", clientId, scope, state);
        
        // Remove `openid` from the scopes to display
        String[] scopesToApprove = StringUtils.delimitedListToStringArray(scope, " ");
        String[] previousApprovedScopes = new String[0];
        
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client != null) {
            OAuth2AuthorizationConsent previousConsent = authorizationConsentService.findById(clientId, principal.getName());
            if (previousConsent != null) {
                previousApprovedScopes = previousConsent.getScopes().toArray(new String[0]);
            }
        }
        
        Map<String, Object> modelMap = new HashMap<>();
        modelMap.put("clientId", clientId);
        modelMap.put("state", state);
        modelMap.put("scopes", scopesToApprove);
        modelMap.put("previousScopes", previousApprovedScopes);
        modelMap.put("principalName", principal.getName());
        
        model.addAllAttributes(modelMap);
        
        return "consent";
    }
}
