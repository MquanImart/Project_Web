<%@ page import="Model.taikhoan" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix="c"%>
<html>

<head>
    <title>Quên mật khẩu</title>
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
		.input-box input{
			padding-left: 3rem;
		}
	</style>
	<link rel="icon" type="image/x-icon" href="${pageContext.request.contextPath}/css/favicon.ico">
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
			<form action="<%=request.getContextPath()%>/sendmail">
            <h1>QUÊN MẬT KHẨU</h1>
            
            <div class="input-box">
				<div class = "box_icon_login"> <i class="fa-solid fa-user fa-2xl"></i> </div>
					<input type="text" name="username" placeholder="Tài khoản" value="<%= request.getAttribute("inputUsername") != null ? request.getAttribute("inputUsername") : "" %>"  maxlength="30" required title="Tài khoản gồm ký tự thường, hoa, số và không quá 30 ký tự">
            </div>
            
            <div class="input-box">
				<div class = "box_icon_login"> <i class="fa-solid fa-envelope fa-2xl"></i></div>
				<input type="email" name="email" placeholder="Gmail" value="<%= request.getAttribute("inputEmail") != null ? request.getAttribute("inputEmail") : "" %>"  maxlength="50" required>
            </div>
				<div class="error_mess" style="color:red;">
					<%String errorMsg = (String) request.getAttribute("error"); %>
					<%if (errorMsg != null) { %>
					<p><%=errorMsg %></p>
					<%} %>
				</div>
				<input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
			<div class = "box_button_login">
				<button type="submit" class="btn btn_gui"><b>Gửi mã</b></button>
			</div>
			</form>

			<form action="<%=request.getContextPath()%>/forgot_post" method="POST">
				<input type="hidden" name="username" value="<%= request.getAttribute("inputUsername") != null ? request.getAttribute("inputUsername") : "" %>">
				<input type="hidden" name="email" value="<%= request.getAttribute("inputEmail") != null ? request.getAttribute("inputEmail") : "" %>">
            <div class="input-box">
				<div class = "box_icon_login"> <i class="fa-solid fa-pen-to-square fa-2xl"></i> </div>
            	<input type="text" name="otp" placeholder="Mã OTP"  maxlength="6" required>
            </div>

            <div class="input-box">
				<div class = "box_icon_login"> <i class="fa-solid fa-lock-open fa-2xl"></i></div>
            	<input type="password" name="newpassword" placeholder="Nhập lại mật khẩu mới"  maxlength="30" required>
            </div>
			<input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
			<div class = "box_button_login"> <button type="submit" class="btn"><b>Xác nhận</b></button> </div>
			</form>
    	</div>
	</div>
<script>
	window.onload = function() {
		// Lấy tất cả các input trừ input type date và password
		var inputs = document.querySelectorAll('input:not([type="email"]):not([type="password"])');

		// Duyệt qua từng input và thêm sự kiện 'input' để kiểm tra giá trị
		inputs.forEach(function(input) {
			input.addEventListener('input', function() {
				// Kiểm tra nếu giá trị chứa ký tự đặc biệt
				if (/[^a-zA-Z0-9\s]/.test(input.value)) {
					// Nếu có, loại bỏ ký tự đặc biệt đó
					input.value = input.value.replace(/[^a-zA-Z0-9\s]/g, '');
				}

				// Kiểm tra giới hạn độ dài tối đa của input
				var maxLength = input.getAttribute('maxlength');
				if (maxLength !== null && input.value.length > maxLength) {
					input.value = input.value.slice(0, maxLength);
				}
			});
		});
		// Lấy input password
		var passwordInput = document.querySelector('input[type="password"]');

		// Thêm sự kiện 'blur' để kiểm tra mật khẩu sau khi người dùng nhập xong
		passwordInput.addEventListener('blur', function() {
			var password = passwordInput.value;

			// Kiểm tra mật khẩu phải chứa ít nhất 8 ký tự, ít nhất 1 chữ hoa, 1 chữ thường, 1 số, và 1 ký tự đặc biệt
			var passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

			if (!passwordPattern.test(password)) {
				// Nếu mật khẩu không đáp ứng yêu cầu
				// Báo cho người dùng và xóa tất cả ký tự trong ô input
				passwordInput.setCustomValidity("Mật khẩu phải chứa ít nhất 8 ký tự, 1 chữ hoa, 1 chữ thường, 1 số, và 1 ký tự đặc biệt");
			} else {
				// Nếu mật khẩu đáp ứng yêu cầu, xóa thông báo lỗi
				passwordInput.setCustomValidity('');
			}
		});
	};
</script>
<%}%>
</body>
</html>