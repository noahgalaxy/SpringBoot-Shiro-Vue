package com.heeexy.example.config.shiro;

import com.alibaba.fastjson.JSONObject;
import com.heeexy.example.util.constants.ErrorEnum;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

/**
 * @author: hxy
 * @description: 对没有登录的请求进行拦截, 全部返回json信息. 覆盖掉shiro原本的跳转login.jsp的拦截方式
 * @date: 2017/10/24 10:11
 */
public class AjaxPermissionsAuthorizationFilter extends FormAuthenticationFilter {

	/**
	 * 这是当没有权限的时候如何处理，直接向页面输出没有权限。
	 * @param request
	 * @param response
	 * @return 返回true表示还要有后面的就方法继续处理，返回false表示到这个拦截器就直接处理了。后面不会再有其他的进行处理；
	 */
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) {
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("code", ErrorEnum.E_20011.getErrorCode());
		jsonObject.put("msg", ErrorEnum.E_20011.getErrorMsg());
		PrintWriter out = null;
		HttpServletResponse res = (HttpServletResponse) response;
		try {
			res.setCharacterEncoding("UTF-8");
			res.setContentType("application/json");
			out = response.getWriter();
			out.println(jsonObject);
		} catch (Exception e) {
		} finally {
			if (null != out) {
				out.flush();
				out.close();
			}
		}
		return false;
	}

	@Bean
	public FilterRegistrationBean registration(AjaxPermissionsAuthorizationFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean(filter);
		registration.setEnabled(false);
		return registration;
	}
}
