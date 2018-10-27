package com.security.ldap.springsecurityldap;

import lombok.Data;

import java.io.Serializable;

@Data
public class LdapProfile implements Serializable {

    private String url;

    private String baseDC;

    private String managerDN;

    private String managerPassword;

    private String userSearchBase;

    private String userSearchFilter;

    private String groupSearchBase;

    private String groupSearchFilter;



}
