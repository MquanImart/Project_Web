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
					<h2>Quản lý phòng ban</h2>
				</div>
				<ul class="navbar-nav ml-auto">
					<li class="nav-item">
						<a href="<%=request.getContextPath()%>/addPhongBan?csrfToken=<%= session.getAttribute("csrfToken") %>">
							<button class="button_icon">
								<i class="fa-sharp fa-solid fa-plus fa-2x" style="display:${sessionScope.capbac == 0 || sessionScope.capbac == 1 ? 'none' : 'inline'}"></i>
							</button>
						</a>
					</li>
				</ul>
			</nav>
			<br>
			<div id="menuContainer" style="display: none;"></div>
			<div class="row">
				<div class="container body">
					<div class="container text-left">
						<div class="form-inline" id="searchForm">
							<div class="form-group mx-2">
								<label for="mapbSelect" class="mr-2"> Mã phòng ban:</label>
								<select class="form-control form-control-sm box_search" id="mapbSelect"
										onchange="searchTable()">
									<!-- Add an empty option -->
									<option value="">- Select -</option>
									<c:forEach items="${listphongban}" var="x">
										<option>${x.mapb}</option>
									</c:forEach>
								</select>
							</div>
							<div class="form-group mx-2">
								<label for="tenpbSelect" class="mr-2">Tên phòng ban:</label>
								<select class="form-control form-control-sm box_search" id="tenpbSelect"
										onchange="searchTable()">
									<!-- Add an empty option -->
									<option value="">- Select -</option>
									<c:forEach items="${listphongban}" var="x">
										<option>${x.tenpb}</option>
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
								<th>Mã Phòng Ban</th>
								<th>Tên Phòng Ban</th>
								<th>Mã Chi Nhánh</th>
								<th>Mã Trưởng Phòng</th>
								<th>Ngày Tạo</th>
								<th>Mã Phòng Ban Cha</th>
								<th>Cập Nhật Phòng Ban</th>
								<th>Xoá phòng ban</th>
							</tr>
							</thead>
							<tbody>
							<c:forEach var="x" items="${listphongban}">
								<tr>
									<td>${x.mapb}</td>
									<td>${x.tenpb}</td>
									<td>${x.macn}</td>
									<td>${x.matrphong}</td>
									<td>${x.ngaytao}</td>
									<td>${x.mapbtr}</td>
									<td><a href="editPhongBan?mapb=<c:out value='${x.mapb}' />&macn=<c:out value='${x.macn}' />&csrfToken=<%= session.getAttribute("csrfToken") %>" style="display:${sessionScope.capbac == 0 || sessionScope.capbac == 1 ? 'none' : 'inline'}" >Edit</a></td>
									<td> <a href="deletePhongBan?mapb=<c:out value='${x.mapb}' />&csrfToken=<%= session.getAttribute("csrfToken") %>" style="display:${sessionScope.capbac == 0 || sessionScope.capbac == 1 ? 'none' : 'inline'}" >Delete</a></td>	&nbsp;&nbsp;
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
		var mapbValue = document.getElementById("mapbSelect").value.toUpperCase();
		var tenpbValue = document.getElementById("tenpbSelect").value.toUpperCase();
		var tableRows = document.getElementsByTagName("tr");

		for (var i = 1; i < tableRows.length; i++) {
			var row = tableRows[i];
			var mapb = row.cells[0].textContent.toUpperCase();
			var tenpb = row.cells[1].textContent.toUpperCase();

			if (mapb.indexOf(mapbValue) > -1 && tenpb.indexOf(tenpbValue) > -1) {
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
