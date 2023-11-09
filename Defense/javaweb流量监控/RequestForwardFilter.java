package com.example.demo.MyFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Enumeration;

public class RequestForwardFilter implements Filter {

    private String forwardIP = "127.0.0.1";
    private String forwardPort = "3307";
    // 设置要转发的特定IP
    // 建议就是自己开个127.0.0.1:3307的http服务接受请求，这样不至于太卡（不接受请求也可以，但是容易超时）

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // 转发请求
        forwardRequest(httpRequest, httpResponse);
        // 继续处理请求
        chain.doFilter(request, response);
    }

    private void forwardRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
        // 将请求转发到特定IP和端口

        try {
            // 将请求转发到特定IP
            URL url = new URL("http://" + forwardIP + ":" + forwardPort + httpRequest.getRequestURI());
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod(httpRequest.getMethod());
            // 设置其他请求头信息，如Content-Type等

            if (httpRequest.getMethod().equals("POST")) {
                // 启用输出
                connection.setDoOutput(true);
                InputStream inputStream = httpRequest.getInputStream();
                OutputStream outputStream = connection.getOutputStream();
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                outputStream.flush();
            }

            // 获取转发请求的响应
            int responseCode = connection.getResponseCode();
        }catch (ConnectException e){
            System.out.println(e);
        }
    }

    @Override
    public void destroy() {
        // 清理资源
    }
}