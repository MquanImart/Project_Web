<%@ page import="Model.taikhoan" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix="c"%>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
        integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
        crossorigin="anonymous" referrerpolicy="no-referrer" />

    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
        integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"
        crossorigin="anonymous">
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/login.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
	<style>
		input { text-transform: none; }
		.error_mess{
			width: 100%; height: 3rem;
			text-align: center;
		}
		.box_form_a{
			margin-top: 1rem;
		}
		.input-box input{
			padding-left: 3rem;
		}
	</style>
	<%
		response.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' https://www.evn.com.vn/userfile/VH/User/huyent_tcdl/images/2021/6/hrmscuatapdoan24621(1).jpeg; frame-src 'none'; frame-ancestors 'none'; media-src 'none'; object-src 'none'; manifest-src 'none'; worker-src 'none'; form-action 'self'");
	%>

</head>
<body>
<%taikhoan username = (taikhoan) session.getAttribute("user"); %>
<%if (username != null) {%>
<jsp:forward page="/trangchu"></jsp:forward>
<%} else {%>
	<div class="container">
		<div class="image">
			<img src="https://www.evn.com.vn/userfile/VH/User/huyent_tcdl/images/2021/6/hrmscuatapdoan24621(1).jpeg" style="width:700px;height:460px;">
		</div>
		<div class="form">
		<form action="<%=request.getContextPath()%>/login_post" method="POST" onsubmit="encryptPassword()">
            <h1>ĐĂNG NHẬP</h1>
            <div class="input-box">
				<div class = "box_icon_login"><i class="fa-solid fa-user fa-2xl"></i></div>
            	<input type="text" name="username" placeholder="Tài khoản" autocomplete=“off” required>
            </div>
            <div class="input-box">
				<div class = "box_icon_login"><i class="fa-solid fa-lock fa-2xl"></i></div>
            	<input type="password" name="password" id="password" placeholder="Mật khẩu" autocomplete=“off” required>
            </div>
			<input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
			<div class="error_mess" style="color:red;">
				<%String errorMsg = (String) request.getAttribute("error"); %>
				<%if (errorMsg != null) { %>
				<p><%=errorMsg %></p>
				<%} %>
			</div>
            <div class="box_show">
				<input type="checkbox" onclick="showpass()"><i>Show pass</i>
            </div>
            <div class = "box_button_login"> <button type="submit" class="btn"><b>Đăng nhập</b></button> </div>
            <div class = "box_form_a">
				<a href="<%=request.getContextPath()%>/forgot" class = "col" >Quên mật khẩu</a>
				<a href="<%=request.getContextPath()%>/change" class = "col" style="text-align: right;" >Đổi mật khẩu</a>
			</div>

        </form>
    	</div>
	</div>
	<script>
		function showpass() {
			var x = document.getElementById("password");
			if (x.type === "password") {
				x.type = "text";
			} else {
				x.type = "password";
			}
		}
	</script>
<%}%>
</body>
</html>