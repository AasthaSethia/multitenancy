package com.example.demo.config;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.representations.adapters.config.AdapterConfig;

import java.io.InputStream;
import java.util.concurrent.ConcurrentHashMap;

public class PathBasedConfigurer implements KeycloakConfigResolver{
        private final ConcurrentHashMap<String, KeycloakDeployment> cache = new ConcurrentHashMap<>();


        private static AdapterConfig adapterConfig;


        @Override
        public KeycloakDeployment resolve(OIDCHttpFacade.Request request) {
            String path = request.getURI();
            String[] realms = path.substring(path.indexOf("://")).split("/");
            if(realms.length>3) {
                String realm = realms[4];
                KeycloakDeployment deployment = cache.get(realm);
                InputStream is = null;
                if (realm.equals("branch1")) {

                    is = getClass().getResourceAsStream("/branch1-realm.json");

                } else if (realm.equals("branch2")) {
                    is = getClass().getResourceAsStream("/branch2-realm.json");
                }
                deployment = KeycloakDeploymentBuilder.build(is);
                return deployment;
            }
            else
            {
                KeycloakDeployment deployment;
                InputStream is = null;
                is = getClass().getResourceAsStream("/branch1-realm.json");
                deployment = KeycloakDeploymentBuilder.build(is);
                return deployment;

            }

        }

        static void setAdapterConfig(AdapterConfig adapterConfig) {
            PathBasedConfigurer.adapterConfig = adapterConfig;
        }
}
