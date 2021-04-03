package com.ab.simple

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.core.env.Environment
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.function.client.WebClient
import javax.servlet.http.HttpServletRequest


@SpringBootApplication
@RestController
class SimpleApplication(private val env: Environment) : WebSecurityConfigurerAdapter() {

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        val handler = SimpleUrlAuthenticationFailureHandler("/")
        // @formatter:off
        http
            .authorizeRequests { authz ->
                authz
                    .antMatchers("/", "/error", "/webjars/**").permitAll()
                    .anyRequest().authenticated()
            }
            .exceptionHandling { e: ExceptionHandlingConfigurer<HttpSecurity?> ->
                e
                    .authenticationEntryPoint(HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            }
            .logout { logoutConfigurer ->
                logoutConfigurer.logoutSuccessUrl("/").permitAll()
            }
            .csrf { it.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) }
            .oauth2Login { o ->
                o.failureHandler { request, response, exception ->
                    request.getSession(true).setAttribute("error.message", exception.message)
                    handler.onAuthenticationFailure(request, response, exception)
                }
            }
        // @formatter:on
    }

    @Bean
    fun rest(clients: ClientRegistrationRepository?, authz: OAuth2AuthorizedClientRepository?): WebClient? {
        val oauth2 = ServletOAuth2AuthorizedClientExchangeFilterFunction(clients, authz)
        return WebClient.builder()
            .filter(oauth2).build()
    }

    @Bean
    fun oauth2UserService(rest: WebClient): OAuth2UserService<OAuth2UserRequest, OAuth2User>? {
        val delegate = DefaultOAuth2UserService()
        return OAuth2UserService { request: OAuth2UserRequest ->
            val user = delegate.loadUser(request)
            println("User")
            println(user)
            if ("github" != request.clientRegistration.registrationId) {
                return@OAuth2UserService user
            }
            val client = OAuth2AuthorizedClient(request.clientRegistration, user.name, request.accessToken)
            val url = user.getAttribute<String>("organizations_url")
            val orgs: MutableList<*>? = rest
                .get().uri(url!!)
                .attributes(oauth2AuthorizedClient(client))
                .retrieve()
                .bodyToMono(MutableList::class.java)
                .block()
            if (orgs?.any { org -> "spring-projects" == (org as Map<*, *>)["login"] }!!) {
                return@OAuth2UserService user
            }
            throw OAuth2AuthenticationException(OAuth2Error("invalid_token", "Not in Spring Team", ""))
        }
    }

    @GetMapping("/user")
    fun getUser(@AuthenticationPrincipal principal: OAuth2User) = mapOf("name" to principal.attributes["name"])

    @GetMapping("/error")
    fun error(request: HttpServletRequest): String? {
        val message = request.session.getAttribute("error.message") as? String
        println("Error message: $message")
        request.session.removeAttribute("error.message")
        return message
    }
}


fun main(args: Array<String>) {
    runApplication<SimpleApplication>(*args)
}



