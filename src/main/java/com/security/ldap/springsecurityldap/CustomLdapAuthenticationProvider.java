package com.security.ldap.springsecurityldap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.HardcodedFilter;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.ldap.filter.Filter;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.naming.directory.DirContext;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class CustomLdapAuthenticationProvider implements AuthenticationProvider {

   private final static  Logger log = LoggerFactory.getLogger(CustomLdapAuthenticationProvider.class);
    Map<String,LdapProfile> ldapProfilesMap = new HashMap<>();

    @PostConstruct
    public void init()
    {
        loadLdapProfilesMap();
    }
    private void loadLdapProfilesMap() {
        ldapProfilesMap.put("local", getLocalLdapProfile());
        ldapProfilesMap.put("cloud", getCloudLdapProfile());

    }

    private LdapProfile getLocalLdapProfile()
    {
        LdapProfile ldapProfile = new LdapProfile();
        ldapProfile.setUrl("ldap://127.0.0.1");
        ldapProfile.setBaseDC("dc=eltaieb,dc=com");
        ldapProfile.setManagerDN("uid=admin,ou=system");
        ldapProfile.setManagerPassword("secret");
        ldapProfile.setUserSearchBase("ou=users");
        ldapProfile.setUserSearchFilter("(uid={0})");
        ldapProfile.setGroupSearchBase("ou=groups");
        ldapProfile.setGroupSearchFilter("(uniqueMember={0})");

        return ldapProfile;
    }


    private LdapProfile getCloudLdapProfile()
    {
        LdapProfile ldapProfile = new LdapProfile();
        ldapProfile.setUrl("ldap://ldap.jumpcloud.com");
        ldapProfile.setBaseDC("dc=jumpcloud,dc=com");

        ldapProfile.setManagerDN("uid=admin,ou=Users,o=5bd4b18e971221647a295b57");
        ldapProfile.setManagerPassword("XXXXXXXXXXXXXXXXXX");

        ldapProfile.setUserSearchBase("ou=Users");
        ldapProfile.setUserSearchFilter("(uid={0})");
        ldapProfile.setGroupSearchBase("");
        ldapProfile.setGroupSearchFilter("");

        return ldapProfile;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        validateAuthentication(authentication);

        String domain = extractDomain(authentication);

        LdapProfile currentDomainProfile = getLdapProfile(domain);

        return  authenticate(authentication,currentDomainProfile);

     }

     private Authentication authenticate(Authentication authentication,LdapProfile currentDomainProfile) throws AuthenticationException{
         LdapContextSource ldapContextSource =  ldapContextSource(currentDomainProfile);
         LdapTemplate ldapTemplate = new LdapTemplate(ldapContextSource);
         String userName = extractUserName(authentication.getName());
         String userDN   = getDnForUser(userName , currentDomainProfile , ldapTemplate);
         boolean authenticationResult = authenticate(userDN,(String)authentication.getCredentials() ,ldapContextSource);
        if(authenticationResult)
        {

            List<String> roles = getUserRoles(userDN , currentDomainProfile , ldapTemplate);
            String[] role = new String[roles.size()];
            for (int i=0;i<roles.size() ; i++)
            {
                role[i]= roles.get(i);
            }
             return new UsernamePasswordAuthenticationToken(authentication.getName(),null , AuthorityUtils.createAuthorityList(role));
        }
        throw new UsernameNotFoundException("");
     }

    private List getUserRoles(String uid, LdapProfile currentDomainProfile, LdapTemplate ldapTemplate) {
        Filter f = new HardcodedFilter(currentDomainProfile.getGroupSearchFilter().replace("{0}",uid));

        List result = ldapTemplate.search(currentDomainProfile.getGroupSearchBase(), f.toString(),
                new AbstractContextMapper() {
                    protected Object doMapFromContext(DirContextOperations ctx) {

                        return ctx.getStringAttribute("cn");
                    }
                });

        return result;
    }

    private String extractUserName(String name) {
        return name.substring(0,name.indexOf("@"));
    }

    public boolean authenticate(String userDn, String credentials,LdapContextSource ldapContextSource) {
        DirContext ctx = null;
        try {
            ctx = ldapContextSource.getContext(userDn, credentials);
            return true;
        } catch (Exception e) {
            // Context creation failed - authentication did not succeed
            log.error("Login failed", e);
            return false;
        } finally {
            // It is imperative that the created DirContext instance is always closed
            LdapUtils.closeContext(ctx);
        }
    }

    private String getDnForUser(String uid, LdapProfile currentDomainProfile, LdapTemplate ldapTemplate) {
        Filter f = new HardcodedFilter(currentDomainProfile.getUserSearchFilter().replace("{0}",uid));

        List result = ldapTemplate.search(currentDomainProfile.getUserSearchBase(), f.toString(),
                new AbstractContextMapper() {
                    protected Object doMapFromContext(DirContextOperations ctx) {
                        return ctx.getNameInNamespace();
                    }
                });

        if(result.size() != 1) {
            throw new RuntimeException("User not found or not unique");
        }

        return (String)result.get(0);
    }

    private LdapProfile getLdapProfile(String domain) {
        return ldapProfilesMap.get(domain);
    }

    private String extractDomain(Authentication authentication) {
      return  authentication.getName().split("@")[1];
    }

    private void validateAuthentication(Authentication authentication) {
        String userName = authentication.getName();
        if(userName == null)
        {
            throw new UsernameNotFoundException("username is required");
        }

        if(!userName.contains("@"))
        {
            throw new UsernameNotFoundException("username must contain @");
        }

        if(Boolean.FALSE == userName.matches("[a-zA-Z0-9]*@[a-zA-Z0-9]*"))
        {
            throw new UsernameNotFoundException("worng username format");

        }


    }


    public LdapContextSource ldapContextSource(LdapProfile ldapProfile ) {

            validateLdapConnection(ldapProfile.getUrl(), ldapProfile.getBaseDC());

            LdapContextSource ldapContextSource = new LdapContextSource();
            ldapContextSource.setUrl(ldapProfile.getUrl());
            ldapContextSource.setBase(ldapProfile.getBaseDC());
            ldapContextSource.setUserDn(ldapProfile.getManagerDN());
            ldapContextSource.setPassword(ldapProfile.getManagerPassword());
            ldapContextSource.afterPropertiesSet();
            return ldapContextSource;

     }

    public void validateLdapConnection(String url, String base) {
        if ((url == null) || url.isEmpty() || (base == null) || base.isEmpty())
        {
            throw new RuntimeException("invalid ldap url or base");
        }

    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }


}
