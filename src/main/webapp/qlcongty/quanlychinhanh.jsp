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
	<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.19.0/font/bootstrap-icons.css" rel="stylesheet">
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
	<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
		  integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"
		  crossorigin="anonymous">
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
					<h2>Quản lý chi nhánh</h2></a>
				</div>
				<ul class="navbar-nav ml-auto">
					<li class="nav-item">
						<a href="<%=request.getContextPath()%>/addChiNhanh?csrfToken=<%= session.getAttribute("csrfToken") %>">
							<button class="button_icon">
								<i class="fa-sharp fa-solid fa-plus fa-2x"></i>
							</button>
						</a>
					</li>
				</ul>
			</nav>
			<br>
			<div class="row">
				<div class="container body">
					<div class="container text-left">
						<div class="form-inline">
							<div class="form-group mx-2">
								<label for="maCNSelect" class="mr-2"> Mã Chi Nhánh:</label>
								<select class="form-control form-control-sm box_search" id="maCNSelect"
										onchange="searchTable()">
									<!-- Add an empty option -->
									<option value="">- Select -</option>
									<c:forEach items="${listchinhanh}" var="x">
										<option>${x.macn}</option>
									</c:forEach>
								</select>
							</div>
							<div class="form-group mx-2">
								<label for="tenCNSelect" class="mr-2">Tên Chi Nhánh:</label>
								<select class="form-control form-control-sm box_search" id="tenCNSelect"
										onchange="searchTable()">
									<!-- Add an empty option -->
									<option value="">- Select -</option>
									<c:forEach items="${listchinhanh}" var="x">
										<option>${x.tencn}</option>
									</c:forEach>
								</select>
							</div>
						</div>
					</div>
					<br>
					<div class="table-container">
						<table class="table table-bordered">
							<thead>
							<tr>
								<th>Mã Chi Nhánh</th>
								<th>Tên Chi Nhánh</th>
								<th>Địa Chỉ</th>
								<th>Mã Giám Đốc</th>
								<th>Tình Trạng</th>
								<th>Ngày Tạo</th>
								<th>Cập Nhật Chi Nhánh</th>
								<th>Xoá Chi Nhánh</th>
							</tr>
							</thead>
							<tbody>
							<c:forEach var="x" items="${listchinhanh}">
								<tr>
									<td>${x.macn}</td>
									<td>${x.tencn}</td>
									<td>${x.diachi}</td>
									<td>${x.magiamdoc}</td>
									<td>${x.tinhtrang}</td>
									<td>${x.ngaytao}</td>
									<td><a href="editChiNhanh?macn=<c:out value='${x.macn}' />&diachi=<c:out value='${x.diachi}' />&csrfToken=<%= session.getAttribute("csrfToken") %>">Edit</a></td>
									<td><a href="deleteChiNhanh?macn=<c:out value='${x.macn}' />&csrfToken=<%= session.getAttribute("csrfToken") %>">Delete</a></td>
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

<script>
	function searchTable() {
		var maCNValue = document.getElementById("maCNSelect").value.toUpperCase();
		var tenCNValue = document.getElementById("tenCNSelect").value.toUpperCase();
		var tableRows = document.getElementsByTagName("tr");

		for (var i = 1; i < tableRows.length; i++) {
			var row = tableRows[i];
			var maCN = row.cells[0].textContent.toUpperCase();
			var tenCN = row.cells[1].textContent.toUpperCase();

			if (maCN.indexOf(maCNValue) > -1 && tenCN.indexOf(tenCNValue) > -1) {
				row.style.display = "";
			} else {
				row.style.display = "none";
			}
		}
	}
</script>
<%}%>
</body>

</html>
