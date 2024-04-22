<%@ page import="Model.taikhoan" %>
<%@ page language="java" contentType="text/html; charset=UTF-8"%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Thông tin cơ bản</title>
    <!-- Linking Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/thongtincoban.css" />
    <link rel="icon" type="image/x-icon" href="${pageContext.request.contextPath}/css/favicon.ico">
    <style>
        .body-infor {
            height: 100px;
        }
    </style>
</head>
<body>
<%taikhoan username = (taikhoan) session.getAttribute("user"); %>
<%if (username == null) {%>
<jsp:forward page="/login/login.jsp"></jsp:forward>
<%} else {%>
<div class="body-infor" style="width: 100%; ">
    <div class="section">
        <i class="fas fa-user"></i>
        <h2> ${tencapbac_header}</h2>
    </div>
    <div class="section">
        <i class="fas fa-users"></i>
        <h2>Phòng ${phongban_header.tenpb}</h2>
    </div>
    <div class="section">
        <i class="fas fa-building"></i>
        <h2>Chi nhánh ${chinhanh_header.tencn}</h2>
    </div>
</div>
<%}%>
</body>
</html>
