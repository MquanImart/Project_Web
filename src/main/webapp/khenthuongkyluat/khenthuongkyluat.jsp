<%@ page import="Model.taikhoan" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix="c"%>
<html>

<head>
    <title>Employee Management</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
        integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
        crossorigin="anonymous" referrerpolicy="no-referrer" />

    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
        integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"
        crossorigin="anonymous">
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/khenthuongkyluat.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
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
                    <div class = "col-11">
                       <h2> Quản lý khen thưởng và kỷ luật </h2>
                    </div>
                    <ul class="navbar-nav ml-auto col-1">
                        <li class="nav-item" >
                            <a class="button_icon" href="<%=request.getContextPath()%>/xemthanhtichkyluat" style="display:${sessionScope.capbac == 0 ? 'none' : 'inline'}">
                               <i class="fa-solid fa-address-book fa-xl"></i>
                            </a>
                        </li>
                    </ul>
                </nav>
                <br>
                <div class="row">
                    <div class="container body">
						<c:set var="count" value="0" />
						<c:forEach var="item" items="${listKTKL}">
						<div class = "box_form">
							<div class = "col box_content">
								<div class="form-group form-inline">
                    				<label for="ngaybatdau${count}" class = "label_form_control">Ngày:</label>
                    				<input type="date" class="form-control box_form_control" id="ngaybatdau${count}" name="ngaybatdau" value="<c:out value="${item.ngay}" />" readonly>
                				</div>
                				<div class="form-group form-inline">
                    				<label for="soqd${count}" class = "label_form_control">Số quyết định:</label>
                    				<input type="text" class="form-control box_form_control" id="soqd${count}" name="soqd" value="<c:out value="${item.soqd}" />" readonly>
                				</div>
								<div class="form-group form-inline">
									<label for="loai${count}" class = "label_form_control">Loaị:</label>
									<input type="text" class="form-control box_form_control" id="loai${count}" name="loai" value="<c:out value="${item.loai}" />" readonly>
								</div>
                				<div class="form-group form-inline">
                    				<label for="noidung${count}" class = "label_form_control">Nội dung:</label>
                    				<textarea class="form-control box_form_control" id="noidung${count}" name="noidung" readonly><c:out value="${item.noidung}" /></textarea>
                				</div>
							</div>
						</div>
						<c:set var="count" value="${count + 1}" />
						</c:forEach>
                    </div>
                </div>
            </div>
        </div>
    </div>
<%}%>
</body>

</html>