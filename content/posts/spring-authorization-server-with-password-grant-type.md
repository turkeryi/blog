---
title: "Spring Authorization Server with Password Grant Type"
date: 2023-08-24T01:19:44+03:00
draft: false
tags: [spring, spring-boot, spring-framework, spring-security, spring-authorization, spring-authorization-server, authorization, password-grant-type, grant-type, password, granttype]
description: Finally, spring-authorization-server got custom grant type support with version 1.0.0.
---

 Finally, `spring-authorization-server` got custom grant type support with version 1.0.0. Let's see what implementations we need to do for `grant-type:password`.

### PasswordGrantAuthenticationConverter

The following example shows a sample implementation of the `AuthenticationConverter`.

```java
public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

  public static final String PASSWORD = "password";

  @Nullable
  @Override
  public Authentication convert(HttpServletRequest request) {
    // grant_type (REQUIRED)
    String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
    if (!PASSWORD.equals(grantType)) {
      return null;
    }

    Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

    MultiValueMap<String, String> parameters = getParameters(request);

    // username and password (REQUIRED)
    String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
    String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
    if (!StringUtils.hasText(username) ||
        !StringUtils.hasText(password) ||
        parameters.get(OAuth2ParameterNames.USERNAME).size() != 1 ||
        parameters.get(OAuth2ParameterNames.PASSWORD).size() != 1) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }

    Map<String, Object> additionalParameters = new HashMap<>();
    parameters.forEach((key, value) -> {
      if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
          !key.equals(OAuth2ParameterNames.CLIENT_ID)) {
        additionalParameters.put(key, value.get(0));
      }
    });

    return new PasswordGrantAuthenticationToken(username, password, clientPrincipal, additionalParameters);
  }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
    Map<String, String[]> parameterMap = request.getParameterMap();
    MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
    parameterMap.forEach((key, values) -> {
      for (String value : values) {
        parameters.add(key, value);
      }
    });
    return parameters;
  }
}
```

### PasswordGrantAuthenticationProvider

`AuthenticationProvider` is responsible for validating the authorization grant. The following example shows a sample implementation.

```java
@RequiredArgsConstructor
public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

  private final OAuth2AuthorizationService authorizationService;
  private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
  private final AuthenticationManager authenticationManager;

  private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
      Authentication authentication) {
    OAuth2ClientAuthenticationToken clientPrincipal = null;
    if (OAuth2ClientAuthenticationToken.class
        .isAssignableFrom(authentication.getPrincipal().getClass())) {
      clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
    }
    if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
      return clientPrincipal;
    }
    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    PasswordGrantAuthenticationToken passwordGrantAuthenticationToken =
        (PasswordGrantAuthenticationToken) authentication;

    // Ensure the client is authenticated
    OAuth2ClientAuthenticationToken clientPrincipal =
        getAuthenticatedClientElseThrowInvalidClient(passwordGrantAuthenticationToken);
    RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

    // Ensure the client is configured to use this authorization grant type
    if (!Objects.requireNonNull(registeredClient).getAuthorizationGrantTypes()
        .contains(passwordGrantAuthenticationToken.getGrantType())) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    // Check user credentials
    String username = passwordGrantAuthenticationToken.getUsername();
    String password = passwordGrantAuthenticationToken.getPassword();

    Authentication credentialsAuthentication;

    try {
      credentialsAuthentication = authenticationManager
          .authenticate(new UsernamePasswordAuthenticationToken(username, password));
    } catch (AuthenticationException e) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    // Get authentication object
    OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken =
        (OAuth2ClientAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
    oAuth2ClientAuthenticationToken.setDetails(credentialsAuthentication.getPrincipal());
    SecurityContextHolder.getContext().setAuthentication(oAuth2ClientAuthenticationToken);


    // Generate the access token
    OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
        .registeredClient(registeredClient)
        .principal(clientPrincipal)
        .authorizationServerContext(AuthorizationServerContextHolder.getContext())
        .tokenType(OAuth2TokenType.ACCESS_TOKEN)
        .authorizationGrantType(passwordGrantAuthenticationToken.getGrantType())
        .authorizationGrant(passwordGrantAuthenticationToken)
        .build();

    OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
    if (generatedAccessToken == null) {
      OAuth2Error error = new OAuth2Error(
          OAuth2ErrorCodes.SERVER_ERROR,
          "The token generator failed to generate the access token.",
          null);
      throw new OAuth2AuthenticationException(error);
    }
    OAuth2AccessToken accessToken = new OAuth2AccessToken(
        OAuth2AccessToken.TokenType.BEARER,
        generatedAccessToken.getTokenValue(),
        generatedAccessToken.getIssuedAt(),
        generatedAccessToken.getExpiresAt(),
        null);

    // Initialize the OAuth2Authorization
    OAuth2Authorization.Builder authorizationBuilder =
        OAuth2Authorization.withRegisteredClient(registeredClient)
            .attribute(Principal.class.getName(), clientPrincipal)
            .principalName(clientPrincipal.getName())
            .authorizationGrantType(passwordGrantAuthenticationToken.getGrantType());
    if (generatedAccessToken instanceof ClaimAccessor) {
      authorizationBuilder.token(accessToken, (metadata) ->
          metadata.put(
              OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
              ((ClaimAccessor) generatedAccessToken).getClaims())
      );
    } else {
      authorizationBuilder.accessToken(accessToken);
    }
    OAuth2Authorization authorization = authorizationBuilder.build();

    // Save the OAuth2Authorization
    this.authorizationService.save(authorization);

    return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
```

### SecurityConfig

The configuration the OAuth2 Token endpoint with the `AuthenticationConverter` and `AuthenticationProvider`.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  public static final String PASSWORD = "password";

  @Bean
  SecurityFilterChain authorizationServerSecurityFilterChain(
      HttpSecurity http,
      OAuth2AuthorizationService authorizationService,
      OAuth2TokenGenerator<?> tokenGenerator,
      AuthenticationManager authenticationManager
  ) throws Exception {

    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
        new OAuth2AuthorizationServerConfigurer();

    authorizationServerConfigurer.tokenEndpoint(tokenEndpoint ->
        tokenEndpoint
            .accessTokenRequestConverter(new PasswordGrantAuthenticationConverter())
            .authenticationProvider(
                new PasswordGrantAuthenticationProvider(authorizationService, tokenGenerator, authenticationManager)
            ));

    RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

    http.securityMatcher(endpointsMatcher)
        .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
        .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
        .apply(authorizationServerConfigurer);

    return http.build();
  }

  @Bean
  RegisteredClientRepository registeredClientRepository() {
    RegisteredClient messagingClient = RegisteredClient
        .withId(UUID.randomUUID().toString())
        .clientId("client")
        .clientSecret(passwordEncoder().encode("secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(new AuthorizationGrantType(PASSWORD))
        .scope("read")
        .scope("write")
        .build();

    return new InMemoryRegisteredClientRepository(messagingClient);
  }

  @Bean
  OAuth2AuthorizationService authorizationService() {
    return new InMemoryOAuth2AuthorizationService();
  }

  @Bean
  OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
    JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
    OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
    OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
    return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }
}
```

### PasswordGrantAuthenticationToken

The sample implementation of `OAuth2AuthorizationGrantAuthenticationToken` for password grant.

```java
@Getter
public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

  public static final String PASSWORD = "password";
  private final String username;
  private final String password;

  public PasswordGrantAuthenticationToken(String username,
                                          String password,
                                          Authentication clientPrincipal,
                                          @Nullable Map<String, Object> additionalParameters) {
    super(new AuthorizationGrantType(PASSWORD), clientPrincipal, additionalParameters);
    Assert.hasText(username, "username cannot be empty");
    Assert.hasText(password, "password cannot be empty");
    this.username = username;
    this.password = password;
  }
}
```

### UserEntity
 
 A basic User Entity.

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "custom_user")
public class UserEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private Long id;

  @Column(unique = true, nullable = false)
  private String username;

  @Column(nullable = false)
  private String password;

  @CreatedDate
  private LocalDateTime createdDate;

  @LastModifiedDate
  private LocalDateTime lastModifiedDate;
}
```

### UserRepository

 A basic User Repository.

```java
public interface UserRepository extends JpaRepository<UserEntity, Long> {

  Optional<UserEntity> findByUsername(String username);
}
```

### UserDetailsImpl

```java
@RequiredArgsConstructor
@AllArgsConstructor
public class UserDetailsImpl implements UserDetails {

  private Long id;
  private String username;
  private String password;
  private Collection<? extends GrantedAuthority> authorities;

  public Long getId() {
    return id;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
```

### UserDetailsServiceImpl

```java
@Getter
@RequiredArgsConstructor
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    UserEntity user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    List<GrantedAuthority> authorities = new ArrayList<>();
    return new UserDetailsImpl(
        user.getId(),
        user.getUsername(),
        user.getPassword(),
        authorities
    );
  }
}
```