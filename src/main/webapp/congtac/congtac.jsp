<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%
    request.setCharacterEncoding("UTF-8");
    response.setCharacterEncoding("UTF-8");
%>

<%@ page import="Model.taikhoan" %>
<%@ page import="Model.congtac" %>
<%@ page import="java.util.UUID" %>
<html>

<head>
    <title>Employee Management</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
          integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
          crossorigin="anonymous" referrerpolicy="no-referrer" />

    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
          integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"
          crossorigin="anonymous">

    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/congtac.css" />
    <style>
        .align_center{
            display: flex; flex-direction: column; justify-content: center;
        }
    </style>
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
        <div class="col-md-11 container_css">
            <jsp:include page="../header_menu/thongtincoban.jsp" />
            <nav class="navbar navbar-expand-md navbar-dark navbar_css">
                <div class = "navbar_item_css">
                    <h2 style="margin-top: 1.5rem;"> Quản lý công tác </h2>
                    <div class="nav-item align_center" >
                        <a href="<%=request.getContextPath()%>/xemcongtac" class="button_icon" style="display:${sessionScope.capbac == 0 ? 'none' : 'inline'}">
                            <i class="fa-solid fa-eye fa-2xl" style="margin-left: 1rem; margin-top: 2.5rem;"></i>
                        </a>
                    </div>
                </div>
            </nav>
            <br>
            <div class="row">
                <div class="container body">
                    <c:set var="count" value="0" />
                    <c:set var="edit" value="0" />
                    <c:forEach var="item_ct" items="${listcongtac}">
                        <form class = "box_form">
                            <div class = "col-md-10 box_content">
                                <div class="form-group form-inline">
                                    <label for="ngaybatdau${count}" class = "label_form_control">Ngày bắt đầu:</label>
                                    <input type="date" value="<c:out value="${item_ct.ngaybatdau}" />" class="form-control box_form_control" id="ngaybatdau${count}" placeholder="Ngày bắt đầu" name="ngaybatdau" readonly required>
                                </div>
                                <div class="form-group form-inline">
                                    <label for="tentochuc${count}" class = "label_form_control">Tên tổ chức:</label>
                                    <input type="text" value="<c:out value="${item_ct.tentochuc}" />" class="form-control box_form_control" id="tentochuc${count}" placeholder="Tên tổ chức" name="tentochuc" readonly required>
                                </div>
                                <div class="form-group form-inline">
                                    <label for="diachi${count}" class = "label_form_control">Địa chỉ:</label>
                                    <input type="text" value="<c:out value="${item_ct.diachi}" />" class="form-control box_form_control" id="diachi${count}" placeholder="Địa chỉ" name="diachi" readonly required>
                                </div>
                                <div class="form-group form-inline">
                                    <label for="chucvu${count}" class = "label_form_control">Chức vụ:</label>
                                    <input type="text" value="<c:out value="${item_ct.chucvu}" />" class="form-control box_form_control" id="chucvu${count}" placeholder="Chức vụ" name="chucvu" readonly required>
                                </div>
                                <div class="form-group form-inline">
                                    <label for="lydo${count}" class = "label_form_control">Lý do:</label>
                                    <input type="text" value="<c:out value="${item_ct.lydo}" />" class="form-control box_form_control" id="lydo${count}" placeholder="Lý do nghỉ" name="lydo" readonly required>
                                </div>
                                <input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
                            </div>
                            <div class = "col-md-1" style=" background-color: white">
                                <button type="button" class = "text_btn" id = "btn_huy${count}" style="display:none;">Hủy</button>
                            </div>
                            <div class = "col-md-1 box_button">
                                <button type="button" class = "button_icon" onclick="openFormXoa${count}()" >
                                    <i class="fa-solid fa-trash fa-2xl"></i>
                                </button>
                                <button type="button" class = "button_icon" id = "btn_edit${count}">
                                    <i class="fa-solid fa-pen-to-square fa-2xl"></i>
                                </button>
                                <button formaction="<%=request.getContextPath()%>/thaydoicongtac" class = "button_icon" id = "btn_save${count}">
                                    <i class="fa-solid fa-floppy-disk fa-2xl"></i>
                                </button>
                            </div>
                            <div class="form_xoa form_tacvu" id="form_xoa${count}">
                                <h3 class = "form_title">Xác nhận xóa </h3>
                                <div class="form-group form-inline">
                                    <h5 class = "label_form_control">Bạn có chắc chắn xóa công tác vào ngày ${item_ct.ngaybatdau} tại tổ chức ${item_ct.tentochuc} không?</h5>
                                    <h5>Bấm Xác nhận để xóa.</h5>
                                </div>
                                <div class="form_button">
                                    <button formaction="<%=request.getContextPath()%>/xoacongtac" type="submit">Xác nhận</button>
                                    <button type="button" onclick="closeFormXoa${count}()">Hủy</button>
                                </div>
                            </div>
                        </form>
                        <script>
                            let ngaybatdau${count} = document.getElementById("ngaybatdau${count}");
                            let tentochuc${count} = document.getElementById("tentochuc${count}");
                            let diachi${count} = document.getElementById("diachi${count}");
                            let chucvu${count} = document.getElementById("chucvu${count}");
                            let lydo${count} = document.getElementById("lydo${count}");

                            let btnedit${count} = document.getElementById("btn_edit${count}");
                            let btnsave${count} = document.getElementById("btn_save${count}");
                            let btnhuy${count} = document.getElementById("btn_huy${count}");

                            btnedit${count}.addEventListener("click", function() {
                                diachi${count}.removeAttribute("readonly");
                                chucvu${count}.removeAttribute("readonly");
                                lydo${count}.removeAttribute("readonly");
                                btnhuy${count}.style.display = "inline";
                                ngaybatdau${count}.focus();
                            });
                            btnhuy${count}.addEventListener("click", function() {
                                window.location.reload ();
                                btnhuy${count}.style.display = "none";
                            });
                            btnsave${count}.addEventListener("click", function() {
                                diachi${count}.setAttribute("readonly", true);
                                chucvu${count}.setAttribute("readonly", true);
                                lydo${count}.setAttribute("readonly", true);

                                btnhuy${count}.style.display = "none";
                            });
                            function openFormXoa${count}() {
                                document.getElementById("form_xoa${count}").style.display = "block";
                            }
                            function closeFormXoa${count}(){
                                document.getElementById("form_xoa${count}").style.display = "none";
                            }
                        </script>
                        <c:set var="count" value="${count + 1}" />
                    </c:forEach>
                    <div class = "col-md-12 box_button_add">
                        <button class = "button_icon" onclick="openFormAdd()">
                            <i class="fa-solid fa-plus fa-2xl"></i>
                        </button>
                    </div>
                </div>
                <div class="form_add form_tacvu" id="add">
                    <form action="<%=request.getContextPath()%>/themcongtac" class="form-container">
                        <h3 class = "form_title">Thêm quá trình công tác </h3>
                        <div class="form-group form-inline">
                            <label for="add_ngaybatdau" class = "label_form_control">Ngày bắt đầu:</label>
                            <input type="date" class="form-control box_form_control" id="add_ngaybatdau" placeholder="Ngày bắt đầu" name="ngaybatdau" required>
                        </div>
                        <div class="form-group form-inline">
                            <label for="add_tentochuc" class = "label_form_control">Tên tổ chức:</label>
                            <input type="text" class="form-control box_form_control" id="add_tentochuc" placeholder="Tên tổ chức" name="tentochuc" required>
                        </div>
                        <div class="form-group form-inline">
                            <label for="add_diachi" class = "label_form_control">Địa chỉ:</label>
                            <input type="text" class="form-control box_form_control" id="add_diachi" placeholder="Địa chỉ" name="diachi" required>
                        </div>
                        <div class="form-group form-inline">
                            <label for="add_chucvu" class = "label_form_control">Chức vụ:</label>
                            <input type="text" class="form-control box_form_control" id="add_chucvu" placeholder="Chức vụ" name="chucvu" required>
                        </div>
                        <div class="form-group form-inline">
                            <label for="add_lydo" class = "label_form_control">Lý do:</label>
                            <input type="text" class="form-control box_form_control"id="add_lydo" placeholder="Lý do nghỉ" name="lydo" required>
                        </div>
                        <input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
                        <div class="form_button">
                            <button type="submit">Xác nhận</button>
                            <button type="button" onclick="closeFormAdd()">Hủy</button>
                        </div>
                    </form>
                </div>
                <script>
                    function openFormAdd() {
                        document.getElementById("add").style.display = "block";
                    }

                    function closeFormAdd() {
                        document.getElementById("add").style.display = "none";
                    }
                </script>
            </div>
        </div>
    </div>
</div>
<%} %>
</body>

</html>
