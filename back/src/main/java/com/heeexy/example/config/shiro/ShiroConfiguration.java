package com.heeexy.example.config.shiro;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import javax.servlet.Filter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author: hxy
 * @description: shiro配置类
 * @date: 2017/10/24 10:10
 */
@Configuration
public class ShiroConfiguration {
	/**
	 * Shiro的Web过滤器Factory 命名:shiroFilter
	 */
//	这个bean是全局过滤器，先走的就是这个，名字必须为shiroFilter
	@Bean(name = "shiroFilter")
	public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		//Shiro的核心安全接口,这个属性是必须的
		shiroFilterFactoryBean.setSecurityManager(securityManager);

		Map<String, Filter> filterMap = new LinkedHashMap<>();

		/*首先使用自定义过滤器，绑定需要authc的链接要经过哪个过滤器*/
		filterMap.put("authc", new AjaxPermissionsAuthorizationFilter());
		shiroFilterFactoryBean.setFilters(filterMap);

		/*定义shiro过滤链  Map结构，而且需要是有序列表-》linkedList，因为是一个请求进来是需要按照顺序进行匹配的
		 * Map中key(xml中是指value值)的第一个'/'代表的路径是相对于HttpServletRequest.getContextPath()的值来的
		 * anon：它对应的过滤器里面是空的,什么都没做,这里.do和.jsp后面的*表示参数,比方说login.jsp?main这种
		 * authc：该过滤器下的页面必须验证后才能访问,它是Shiro内置的一个拦截器org.apache.shiro.web.filter.authc.FormAuthenticationFilter
		 * perms：表示需要拥有权限，如下：
		 * 		 "perms[article:list,user:list,user:add]"
		 * 		 表示这个链接需要有article:list、user:list等这几个权限才能访问，
		 * 		 而权限就是在Realm的授权阶段将这些权限放到SimpleAuthorizationInfo进去；
		 * 		 通过SimpleAuthorizationInfo.addStringPermission进行添加；
		 * roles：表示需要有以下角色才能访问，如下：
		 * 		 "roles[adminstrator, manager]"
		 * 		 表示这个链接需要有列表里面的角色才能访问，去角色表查；
		 * 		 这些角色也是在Realm的授权阶段将这些角色放到SimpleAuthorizationInfo进去；
		 * 		 通过SimpleAuthorizationInfo.addRole()进行添加；
		 */

		Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();

         /* 过滤链定义，从上向下顺序执行，一般将 / ** 放在最为下边:这是一个坑呢，一不小心代码就不好使了;
          authc:所有url都必须认证（也就是登陆，authc表示登陆）通过才可以访问，都必须通过authc这个过滤器进行认证过滤; anon:所有url都都可以匿名访问 */

		filterChainDefinitionMap.put("/", "anon");
		filterChainDefinitionMap.put("/static/**", "anon");
		filterChainDefinitionMap.put("/login/auth", "anon");
		filterChainDefinitionMap.put("/login/logout", "anon");
		filterChainDefinitionMap.put("/error", "anon");

//		authc代表使用authc这个过滤器，这个过滤器在后面又被重写了
		filterChainDefinitionMap.put("/**", "authc");
		shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
		return shiroFilterFactoryBean;
	}

	/**
	 * 不指定名字的话，自动创建一个方法名第一个字母小写的bean
	 */
	@Bean
	public SecurityManager securityManager() {
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		securityManager.setRealm(userRealm());
		return securityManager;
	}

	/**
	 * Shiro Realm 继承自AuthorizingRealm的自定义Realm,即指定Shiro验证用户登录的类为自定义的
	 */
	@Bean
	public UserRealm userRealm() {
		UserRealm userRealm = new UserRealm();
		/*
		如果数据库里面是用hash加密的话，这里就需要给Realm传入一个密码匹配器

		userRealm.setCredentialsMatcher(this.hashedCredentialsMatcher());

		 */
		return userRealm;
	}

	/**
	 * 凭证匹配器
	 * （由于我们的密码校验交给Shiro的SimpleAuthenticationInfo进行处理了
	 * 所以我们需要修改下doGetAuthenticationInfo中的代码;
	 * ）
	 * 可以扩展凭证匹配器，实现 输入密码错误次数后锁定等功能，下一次
	 */
	@Bean(name = "credentialsMatcher")
	public HashedCredentialsMatcher hashedCredentialsMatcher() {
		HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
		//散列算法:这里使用MD5算法;
		hashedCredentialsMatcher.setHashAlgorithmName("md5");
		//散列的次数，比如散列两次，相当于 md5(md5(""));
		hashedCredentialsMatcher.setHashIterations(2);
		//storedCredentialsHexEncoded默认是true，此时用的是密码加密用的是Hex编码；false时用Base64编码
		hashedCredentialsMatcher.setStoredCredentialsHexEncoded(true);
		return hashedCredentialsMatcher;
	}

	/**
	 * Shiro生命周期处理器
	 */
	@Bean
	public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
		return new LifecycleBeanPostProcessor();
	}

	/**
	 * 开启Shiro的注解(如@RequiresRoles,@RequiresPermissions),需借助SpringAOP扫描使用Shiro注解的类,并在必要时进行安全逻辑验证
	 * 配置以下两个bean(DefaultAdvisorAutoProxyCreator(可选)和AuthorizationAttributeSourceAdvisor)即可实现此功能
	 */
	@Bean
	@DependsOn({"lifecycleBeanPostProcessor"})
	public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator() {
		DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
		advisorAutoProxyCreator.setProxyTargetClass(true);
		return advisorAutoProxyCreator;
	}

	@Bean
	public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor() {
		AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
		authorizationAttributeSourceAdvisor.setSecurityManager(securityManager());
		return authorizationAttributeSourceAdvisor;
	}
}
