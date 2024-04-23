<%@ page import="Model.taikhoan" %>
<%@ page language="java" contentType="text/html; charset=UTF-8"
		 pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<html>

<head>
	<title>Employee Management</title>
	<!-- Include your existing CSS and JS links -->
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
		  integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
		  crossorigin="anonymous" referrerpolicy="no-referrer" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
	<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
		  integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"
		  crossorigin="anonymous">
	<link rel="icon" type="image/x-icon" href="${pageContext.request.contextPath}/css/favicon.ico">
</head>

<body>
<%taikhoan username = (taikhoan) session.getAttribute("user"); %>
<%if (username == null) {%>
<jsp:forward page="/login/login.jsp"></jsp:forward>
<%} else {%>
<jsp:include page="../header_menu/header.jsp" />
<div class="container">
	<div class="row">
		<div class="col-md-1">
			<jsp:include page="../header_menu/menu.jsp" />
		</div>
		<div class="col-md-11">
			<jsp:include page="../header_menu/thongtincoban.jsp" />
			<nav class="navbar navbar-expand-md navbar-dark navbar_css">
				<div>
					<h2>Thêm nhân viên</h2>
				</div>
				<ul class="navbar-nav ml-auto">
					<li class="nav-item">
						<a href="<%=request.getContextPath()%>/themnhanvienexcel">
							<button class="button_icon">
								<i class="fa-solid fa-floppy-disk fa-2x"></i>
							</button>
						</a>
					</li>
				</ul>
			</nav>
			<br>
			<div class="row">
				<div class="container body">
					<div class="table-container">
						<table class="table table-bordered">
							<thead>
							<tr>
								<th>Họ tên</th>
								<th>ngày sinh</th>
								<th>giới tính</th>
								<th>số cccd</th>
								<th>ngày cấp</th>
								<th>tỉnh cấp</th>
								<th>huyện cấp</th>
								<th>xã cấp</th>
								<th>số nhà cấp</th>
								<th>tỉnh/thành phố</th>
								<th>huyện/quận</th>
								<th>xã/phường</th>
								<th>số nhà</th>
								<th>SDT</th>
								<th>Email</th>
								<th>Username</th>
								<th>password</th>
								<th>công việc</th>
								<th>phòng ban</th>
								<th>chi nhánh</th>
								<th>bằng cấp</th>
								<th>ngày bắt đầu</th>
							</tr>
							</thead>
							<tbody>
							<c:forEach var="x" items="${list_dulieunhanvien}">
								<tr>
									<td>${x.hoten}</td>
									<td>${x.ngaysinh}</td>
									<td>${x.gioitinh}</td>
									<td>${x.socccd}</td>
									<td>${x.ngaycap}</td>
									<td>${x.tinh_cap}</td>
									<td>${x.huyen_cap}</td>
									<td>${x.xa_cap}</td>
									<td>${x.sonha_cap}</td>
									<td>${x.tinh}</td>
									<td>${x.huyen}</td>
									<td>${x.xa}</td>
									<td>${x.sonha}</td>
									<td>${x.sdt}</td>
									<td>${x.email}</td>
									<td>${x.usernam}</td>
									<td>${x.pass}</td>
									<td>${x.congviec}</td>
									<td>${x.phongban}</td>
									<td>${x.chinhanh}</td>
									<td>${x.bangcap}</td>
									<td>${x.ngaybatdau}</td>
								</tr>
							</c:forEach>
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>
<%}%>
</body>

</html>
