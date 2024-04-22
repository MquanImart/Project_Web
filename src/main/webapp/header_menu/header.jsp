<%@ page import="Model.taikhoan" %>
<%@ page language="java" contentType="text/html; charset=UTF-8"%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Header</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/header.css" />
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
    <link rel="icon" type="image/x-icon" href="${pageContext.request.contextPath}/css/favicon.ico">
</head>
<body>
<%taikhoan username = (taikhoan) session.getAttribute("user"); %>
<%if (username == null) {%>
<jsp:forward page="/login/login.jsp"></jsp:forward>
<%} else {%>
<div class="box-area">
    <header>
        <div class="wrapper">
            <div class="logo-header">
                <a href="#">Quản lý nhân sự</a>
            </div>
        </div>
    </header>
</div>
<%}%>
</body>
</html>
