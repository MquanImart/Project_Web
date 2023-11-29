<%@ page language="java" contentType="text/html; charset=UTF-8"%>
<!DOCTYPE html>
<!-- Coding By CodingNepal - www.codingnepalweb.com -->
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sidebar</title>
    <!-- Linking Google font link for icons -->
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200">
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/menu.css" />
</head>
<body>
<aside class="sidebar">
    <div class="logo">
        <img src="fuk.jpeg" alt="logo">
        <h2>Nguyễn Bảo Quốc</h2>
    </div>
    <ul class="links">
        <li>
            <span class="material-symbols-outlined">dashboard</span>
            <a href="<%=request.getContextPath()%>/trangchu" >Trang chủ</a>
        </li>
        <li>
            <span class="material-symbols-outlined">show_chart</span>
            <a href="<%=request.getContextPath()%>/thongtincanhan">Thông tin cá nhân</a>
        </li>
        <li>
            <span class="material-symbols-outlined">flag</span>
            <a href="<%=request.getContextPath()%>/congtac">Công tác</a>
        </li>
        <li>
            <span class="material-symbols-outlined">person</span>
            <a href="<%=request.getContextPath()%>/khenthuongkyluat">Khen thưởng kỉ luật</a>
        </li>
        <li>
            <span class="material-symbols-outlined">group</span>
            <a href="<%=request.getContextPath()%>/quanlynhanvien">Quản lý nhân viên </a>
        </li>
        <li>
            <span class="material-symbols-outlined">ambient_screen</span>
            <a href="<%=request.getContextPath()%>/quanlyphongban">Quản lí phòng ban</a>
        </li>
        <li>
            <span class="material-symbols-outlined">pacemaker</span>
            <a href="<%=request.getContextPath()%>/quanlychinhanh">Quản lí chi nhánh</a>
        </li>
        <hr>
        <li class="logout-link">
            <span class="material-symbols-outlined">logout</span>
            <a href="<%=request.getContextPath()%>/logout">Logout</a>
        </li>
    </ul>
</aside>
</body>
</html>
