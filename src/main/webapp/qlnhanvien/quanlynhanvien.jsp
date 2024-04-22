<%@ page import="DAO.yeucauDAO" %>
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
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/quanlynhanvien.css" />
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/form.css" />
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
                    <div class = "col-10">
                       <h2> Quản lý nhân viên </h2>
                    </div>
                    <ul class="navbar-nav ml-auto col-2">
                    	<li class="nav-item" style="display:${sessionScope.capbac <= 1 ? 'none' : 'inline'}">
                            <c:set var="file_excel" value="" />
                            <form action="<%=request.getContextPath()%>/readExcelNhanVien" method="post" enctype="multipart/form-data" id = "form_excel">
                                <button class="button_icon" id = "choose-file" type="button">
                              	    <i class="fa-solid fa-file-excel fa-2x"></i>
                                </button>
                                <input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
                                <input type="file" id="file-input" name="file" style="display: none">
                            </form>
                            <script>
                                let fileInput = document.getElementById("file-input");
                                let chooseFile = document.getElementById("choose-file");
                                let form = document.getElementById("form_excel");
                                chooseFile.onclick = function() {
                                    fileInput.click();
                                    return false;
                                }
                                fileInput.onchange = function() {
                                    if (fileInput.files.length > 0) {
                                        form.submit();
                                    }
                                }
                            </script>
                        </li>
                        <li class="nav-item" >
                            <button class="button_icon" onclick="openFormNotify()">
                               <i class="fa-solid fa-bell fa-2xl"></i>
                            </button>
                        </li>
                    </ul>
                </nav>
                <br>
                <div class="row">
                    <div class="container body">
                    	<div class="container text-left">
                            <div class="form-inline">
                                <div class="form-group mx-3">
                                    <label for="search" class="mr-2"> Tìm kiếm:</label>
                                    <input class = "form-control box_search" id = "search" onkeyup="Search_textbox()" placeholder="Search">
                                </div>
                                <div class="form-group mx-2">
                                    <label for="select_macn" class="mr-2"> Mã chi nhánh:</label>
                                    <select class="form-control form-control-sm box_search" id = "select_macn"  onchange="updatePhongBanList(); Search_combobox();">
                                        <option value="ALL">Tất cả</option>
                                        <c:forEach var="item" items="${setmacn_nv}">
                                            <option value="<c:out value="${item}" />">${item}</option>
                                        </c:forEach>
                                    </select>
                                </div>
                                <div class="form-group mx-2">
                                    <label for="select_mapb" class="mr-2"> Mã phòng ban:</label>
                                    <select class="form-control form-control-sm box_search" id = "select_mapb" onchange = "Search_combobox()" >
                                        <option value="ALL">Tất cả</option>
                                        <c:forEach var="item" items="${setmapb_nv}">
                                            <option value="<c:out value="${item}" />">${item}</option>
                                        </c:forEach>
                                    </select>
                                </div>
                                <c:set var="capbac" value="${capbac}" />
                                <c:if test="${capbac > 1}">
                                    <div class="form-group mx-4">
                                        <a class = "button_add" href="<%=request.getContextPath()%>/themnhanvien?&csrfToken=<%= session.getAttribute("csrfToken") %>" style="text-decoration: none; text-align: center;">Thêm nhân viên</a>
                                    </div>
                                </c:if>
                                <c:if test="${capbac == 1}">
                                    <div class="form-group mx-4">
                                        <button type="button" class = "button_add" onclick="openFormRequest()">Yêu cầu thêm nhân viên</button>
                                    </div>
                                </c:if>
                            </div>
                        </div>
                        <br>
                        <table class="table table-bordered">
                            <thead>
                                <tr>
                                    <th>Mã nhân viên</th>
				                    <th>Mã phòng ban</th>
				                    <th>Mã Chi Nhánh</th>
				                    <th>Ngày bắt đầu</th>
				                    <th>Tình trạng </th>
                                    <th>Công Việc </th>
				                    <th>SA THẢI</th>
				                    <th>XEM THÊM</th>
                                    <th>CẬP NHẬT</th>
                                    <c:if test="${capbac > 1}">
                                        <th>CHỈ ĐỊNH</th>
                                    </c:if>
                                </tr>
                            </thead>
                            <tbody id = "row_table">
                            <c:set var="count" value="0" />
                            <c:forEach var="x" items="${listnv}">
                                <tr>
                                    <td>${x.matk}</td>
                                    <td>${x.mapb}</td>
                                    <td>${x.macn}</td>
                                    <td>${x.ngaybatdau}</td>
                                    <td>${x.tinhtrang}</td>
                                    <td>${x.congviec}</td>
                                    <td><button onclick="openFormXoa${count}()">Sa thải</button></td>
                                    <td><a href="xemthongtinnhanvien?matk=<c:out value='${x.matk}'/>&csrfToken=<%= session.getAttribute("csrfToken") %>">Xem thêm</a></td>
                                    <td><button onclick="openFormTinhTrang${count}()">Trạng thái</button></td>
                                    <c:if test="${capbac > 1}">
                                        <td><button onclick="openFormChiDinh${count}()">Chỉ định</button></td>
                                    </c:if>
                                </tr>
                                <div class = "form_sathai form_tacvu" id = "form_sathai${count}">
                                    <h3 class = "form_title">Xác nhận sa thải </h3>
                                    <div class="form-group form-inline">
                                        <h5 class = "label_form_control">Bạn có chắc chắn sa thải nhân viên ${x.matk} không?</h5>
                                        <h5>Bấm Xác nhận để xóa.</h5>
                                    </div>
                                    <div class="form_button">
                                        <a href="<%=request.getContextPath()%>/sathainhanvien?matk=<c:out value='${x.matk}'/>&csrfToken=<%= session.getAttribute("csrfToken") %>">Xác nhận</a>
                                        <button type="button" onclick="closeFormXoa${count}()">Hủy</button>
                                    </div>
                                </div>
                                <div class = "form_chidinhcongviec form_tacvu" id = "form_chidinh${count}" >
                                    <form action="<%=request.getContextPath()%>/chidinhnhanvien">
                                        <h3 class = "form_title">Chỉ định nhân viên </h3>
                                        <div class="form-group form-inline" style="display: none;">
                                            <label for="matk${count}" class = "label_form_control"><b>Mã tài khoản:</b></label>
                                            <input type="text" value="<c:out value='${x.matk}' />" class="form-control" id="matk${count}" placeholder="Công việc" name="matk" required>
                                        </div>
                                        <div class="form-group form-inline">
                                            <label for="macn${count}" class = "label_form_control"><b>Mã chi nhánh:</b></label>
                                            <select id="macn${count}" name="macn" class="form-control box_form_control form-select">
                                                <option value="all">Tất cả</option>
                                                <c:forEach var="item" items="${setmacn_nv}">
                                                    <option value="<c:out value="${item}" />">${item}</option>
                                                </c:forEach>
                                            </select>
                                        </div>
                                        <div class="form-group form-inline">
                                            <label for="mapb${count}" class = "label_form_control"><b>Mã phòng ban:</b></label>
                                            <select id="mapb${count}" name="mapb" class="form-control box_form_control form-select">
                                                <option value="all">Tất cả</option>
                                                <c:forEach var="item" items="${chitietphongban}">
                                                    <option value="<c:out value="${item.mapb}" />">${item.mapb}</option>
                                                </c:forEach>
                                            </select>
                                        </div>
                                        <div class="form-group form-inline">
                                            <label for="congviec${count}" class = "label_form_control"><b>Công việc:</b></label>
                                            <input type="text" class="form-control" id="congviec${count}" placeholder="Công việc" name="congviec" required>
                                        </div>
                                        <input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
                                        <div class="form_button">
                                            <button type="submit">Xác nhận</button>
                                            <button type="button" onclick="closeFormChiDinh${count}()">Hủy</button>
                                        </div>
                                    </form>
                                </div>
                                <div class = "form_tinhtrang form_tacvu" id = "form_trangthai${count}" >
                                    <form action="<%=request.getContextPath()%>/editnhanvien">
                                        <h3 class = "form_title">Thay đổi thông tin </h3>
                                        <div class="form-group form-inline" style="display: none;">
                                            <label for="matk_tt${count}" class = "label_form_control"><b>Mã tài khoản:</b></label>
                                            <input type="text" value="<c:out value='${x.matk}' />" class="form-control" id="matk_tt${count}" placeholder="Công việc" name="matk_tt" required>
                                        </div>
                                        <div class="form-group form-inline">
                                            <label for="tinhtrang_tt${count}" class = "label_form_control"><b>Tình trạng:</b></label>
                                            <select id="tinhtrang_tt${count}" name="tinhtrang_tt" class="form-control box_form_control form-select">
                                                <option value="Đang hoạt động">Đang Hoạt Động</option>
                                                <option value="Nghỉ phép">Nghỉ Phép</option>
                                                <option value="Nghỉ việc">Nghỉ Việc</option>
                                            </select>
                                        </div>
                                        <input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
                                        <div class="form_button">
                                            <button type="submit">Xác nhận</button>
                                            <button type="button" onclick="closeFormTinhTrang${count}()">Hủy</button>
                                        </div>
                                    </form>
                                </div>
                                <script>
                                    function openFormXoa${count}() {
                                        document.getElementById("form_sathai${count}").style.display = "block";
                                    }
                                    function closeFormXoa${count}(){
                                        document.getElementById("form_sathai${count}").style.display = "none";
                                    }
                                    function openFormChiDinh${count}() {
                                        document.getElementById("form_chidinh${count}").style.display = "block";
                                    }
                                    function closeFormChiDinh${count}(){
                                        document.getElementById("form_chidinh${count}").style.display = "none";
                                    }
                                    function openFormTinhTrang${count}() {
                                        document.getElementById("form_trangthai${count}").style.display = "block";
                                    }
                                    function closeFormTinhTrang${count}(){
                                        document.getElementById("form_trangthai${count}").style.display = "none";
                                    }
                                </script>
                            <c:set var="count" value="${count + 1}"/>
                            </c:forEach>
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="form_yeucau" id="yeucau">
                        <form action="<%=request.getContextPath()%>/themyeucau" class="form-container">
                            <h3 class = "form_title">Yêu cầu nhân viên</h3>
                            <div class="form-group form-inline">
                                <label for="tencongviec" class = "label_form_control"><b>Công Việc:</b></label>
                                <input type="text" class="form-control" id="tencongviec" placeholder="Tên công việc" name="congviec" required>
                            </div>
                            <div class="form_button">
                                <button type="submit">Xác nhận</button>
                                <button type="button" onclick="closeFormRequest()">Hủy</button>
                            </div>
                            <input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
                        </form>
                    </div>

                    <div class="form_thongbao" id="thongbao">
                        <ul>
                            <c:set var="count" value="0" />
                            <c:forEach var="x" items="${listyeucau}">
                        	<li>
                        		<p class = "box_noidung_thongbao">Trưởng phòng ban ${x.mapb} yêu cầu thêm nhân viên ${x.congviec}</p>
                                <div class = "box_tinhtrang_thongbao">${x.tinhtrang}</div>
                                <div class = "box_check_thongbao" style="display:${sessionScope.capbac == 2 && x.tinhtrang == "chưa duyệt" ? 'inline' : 'none'}">
                                    <a href="<%=request.getContextPath()%>/duyetyeucau?mayeucau=<c:out value='${x.mayeucau}' />"><i class="fa-solid fa-check fa-xs greencolor"></i></a>
                                    <a href="<%=request.getContextPath()%>/tuchoiyeucau?mayeucau=<c:out value='${x.mayeucau}' />"><i class="fa-solid fa-x fa-xs redcolor"></i></a>
                                </div>
                        	</li>
                            <c:set var="count" value="${count + 1}"/>
                            </c:forEach>
                        </ul>
                        <div class="form_button box_button_thongbao">
                           <button type="button" onclick="closeFormNotify()">Đóng</button>
                        </div>
                    </div>
                    
                    <script>
                        function openFormRequest() {
                          	document.getElementById("yeucau").style.display = "block";
                        }

                        function closeFormRequest() {
                          	document.getElementById("yeucau").style.display = "none";
                        }
                        function openFormNotify() {
                          	document.getElementById("thongbao").style.display = "block";
                        }

                        function closeFormNotify() {
                          	document.getElementById("thongbao").style.display = "none";
                        }
                        function Search_textbox() {
                            var input, filter, table, tr, td, i, txtValue;
                            input = document.getElementById("search");
                            filter = input.value.toUpperCase();
                            table = document.getElementById("row_table");
                            tr = table.getElementsByTagName("tr");
                            for (i = 0; i < tr.length; i++) {
                                td = tr[i].getElementsByTagName("td");
                                let j = 0;
                                for (j = 0; j < td.length; j++){
                                    let x = tr[i].getElementsByTagName("td")[j];
                                    if (x) {
                                        txtValue = x.textContent || x.innerText;
                                        if (txtValue.toUpperCase().indexOf(filter) > -1) {
                                            tr[i].style.display = "";
                                            break;
                                        } else {
                                            tr[i].style.display = "none";
                                        }
                                    }
                                }
                            }
                        }
                        function Search_combobox() {
                            var input, filter, table, tr, td, i, txtValue;
                            input = document.getElementById("search");
                            filter = input.value.toUpperCase();
                            table = document.getElementById("row_table");
                            tr = table.getElementsByTagName("tr");

                            var selectMacn = document.getElementById("select_macn");
                            var selectMapb = document.getElementById("select_mapb");
                            var selectedMacn = selectMacn.options[selectMacn.selectedIndex].value.toUpperCase();
                            var selectedMapb = selectMapb.options[selectMapb.selectedIndex].value.toUpperCase();

                            for (i = 0; i < tr.length; i++) {
                                td = tr[i].getElementsByTagName("td");
                                let macnValue = td[2].textContent || td[2].innerText; // Assuming the column index for Mã Chi Nhánh is 2
                                let mapbValue = td[1].textContent || td[1].innerText; // Assuming the column index for Mã Phòng Ban is 1

                                if (
                                    (selectedMacn === "ALL" || macnValue.toUpperCase() === selectedMacn) &&
                                    (selectedMapb === "ALL" || mapbValue.toUpperCase() === selectedMapb) &&
                                    (filter === "" || (td[0] && (td[0].textContent || td[0].innerText).toUpperCase().indexOf(filter) > -1))
                                ) {
                                    tr[i].style.display = "";
                                } else {
                                    tr[i].style.display = "none";
                                }
                            }
                        }


                        function updatePhongBanList() {
                            var mainComboValue = document.getElementById("select_macn").value;
                            var mapbSelect = document.getElementById('select_mapb');

                            // Use AJAX to send macnValue to the server and update dependent combobox
                            var xhr = new XMLHttpRequest();
                            xhr.open("GET", "quanlynhanvien?mainComboValue=" + encodeURIComponent(mainComboValue), true);
                            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                            xhr.onreadystatechange = function () {
                                if (xhr.readyState == 4 && xhr.status == 200) {
                                    var options = JSON.parse(xhr.responseText);
                                    // Remove all existing options
                                    options.unshift("Tất cả");
                                    while (mapbSelect.firstChild) {
                                        mapbSelect.removeChild(mapbSelect.firstChild);
                                    }

                                    // Add the new options to mapbSelect
                                    options.forEach(function (option) {
                                        var newOption = document.createElement('option');
                                        newOption.text = option;
                                        mapbSelect.add(newOption);
                                    });
                                }
                            };
                            xhr.send();
                        }
                   	</script>
                    <script type="text/javascript">
                        document.getElementById('select_macn').addEventListener('change', function() {
                            if (this.value === 'ALL') {
                                location.reload();
                            }
                        });
                    </script>
                </div>
            </div>
        </div>
    </div>
<%}%>
</body>

</html>
