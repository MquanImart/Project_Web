<%@ page import="Model.taikhoan" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix= "c" uri= "http://java.sun.com/jsp/jstl/core" %>
<html>

<head>
    <title>Thông tin cá nhân</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
        integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
        crossorigin="anonymous" referrerpolicy="no-referrer" />

    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
        integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"
        crossorigin="anonymous">
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/thongtincanhan.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/thongtincanhanform.css" />
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
                       <h2> Thông tin cá nhân </h2>
                    </div>
                    <ul class="navbar-nav ml-auto col-2">
                        <li class="nav-item" >
                            <button type="button" class="button_icon" id="btn_suathongtin">
                               <i class="fa-solid fa-pen-to-square fa-2xl"></i>
                            </button>
                        </li>
                    </ul>
                </nav>
                <br>
                <form class="row">
                    <div class="container body container_css">
						<div class = "col">
							<div class="box_info">
								<p class="style_text"><b>Thông tin nhân viên</b></p>
							</div>
					
							<div class="box_info">
								<div class="form-group form-inline">
									<label for="matk"><b>Mã NV:</b></label>
									<input type="text" class=" control" id="matk" placeholder="Mã NV" name="matk" value="${thongtincanhan.matk}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="hoten"><b>Họ và tên:</b></label>
									<input type="text" class=" control" id="hoten" placeholder="Họ và tên" name="hoten" value="${thongtincanhan.hoten}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="ngaysinh"><b>Ngày sinh:</b></label>
									<input type="date" class=" control" id="ngaysinh" placeholder="Ngày sinh" name="ngaysinh" value="${thongtincanhan.ngaysinh}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="gioitinh"><b>Giới tính:</b></label>
									<input type="text" class=" control" id="gioitinh" placeholder="Giới tính"name="gioitinh" value="${thongtincanhan.gioitinh}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="cccd" ><b>Số CCCD:</b></label>
									<input type="text" class=" control" id="cccd" placeholder="Số CCCD" name="cccd" value="${cancuoc.cccd}" readonly required>
									<button type="button" class = "button_show" onclick="openFormCC()">
										<i class="fa-solid fa-plus fa-sm"></i>
									</button>
								</div>
								<div class="form-group form-inline">
									<label for="diachi" ><b>Địa chỉ:</b></label>
									<input type="text" class=" control" id="diachi" placeholder="Địa chỉ" name="diachi" value="${thongtincanhan.diachi}" readonly required>
									<button type="button" class = "button_show" onclick="openFormDC()">
										<i class="fa-solid fa-plus fa-sm"></i>
									</button>
								</div>
							</div>
						</div>
						<div class = "col">
							<div class="box_info">
								<p class="style_text"><b>Thông tin liên lạc</b></p>
							</div>
					
							<div class="box_info">
								<div class="form-group form-inline">
									<label for="sdt"><b>Số điện thoại:</b></label>
									<input type="text" class="control" id="sdt" placeholder="Số điện thoại" name="sdt" value="${thongtincanhan.sdt}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="email"><b>Email:</b></label>
									<input type="email" class="control" id="email" placeholder="Email" name="email" value="${thongtincanhan.email}" readonly required>
								</div>
								<br>
								<div class="form-group form-inline">
									<label for="username"><b>Tên tài khoản:</b></label>
									<input type="text" class="control" id="username" placeholder="Tên tài khoản" name="username" value="${taikhoan.username}" readonly required>
								</div>
							</div>
						</div>
				
						<div class = "col">
							<div class="box_info">
								<p class="style_text"><b>Thông tin chức vụ</b></p>
							</div>
					
							<div class="box_info">
								<div class="form-group form-inline">
									<label for="congviec"><b>Công việc:</b></label>
									<input type="text" class="control" id="congviec" placeholder="Công việc" name="congviec" value="${congviec}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="chucvu"><b>Chức vụ:</b></label>
									<input type="text" class="control" id="chucvu" placeholder="Chức vụ" name="chucvu" value="${chucvu}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="phongban"><b>Phòng ban:</b></label>
									<input type="text" class="control" id="phongban" placeholder="Phòng ban" name="phongban" value="${tenpb}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="chinhanh"><b>Chi nhánh:</b></label>
									<input type="text" class="control" id="chinhanh" placeholder="Chi nhánh" name="chinhanh" value="${tencn}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="capbac"><b>Cấp bậc:</b></label>
									<input type="text" class="control" id="capbac" placeholder="Cấp bậc" name="bangcap" value="${thongtincanhan.bangcap}"  readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="ngaybatdau"><b>Ngày bắt đầu:</b></label>
									<input type="date" class="control" id="ngaybatdau" placeholder="Ngày bắt đầu" name="ngaybatdau" value="${ngaybatdau}" readonly required>
								</div>
							</div>
						</div>
                    </div>
					<div>
						<button class="button_luu" formaction="<%=request.getContextPath()%>/thaydoithongtin"  id="btn_save">
							<i class="fa-solid fa-floppy-disk fa-2xl"></i>
						</button>
					</div>
                </form>
				<div class="form_add form_tacvu" id="xemcc">
					<form action="<%=request.getContextPath()%>/thaydoicccd" class="form-container">
						<h3 class = "form_title">CCCD</h3>
						<div class="form-group form-inline">
							<label for="cc_cccd" class = "label_form_control">CCCD:</label>
							<input type="text" class="form-control box_form_control" id="cc_cccd" placeholder="CCCD" name="cc_cccd" value="${cancuoc.cccd}" readonly required>
						</div>
						<div class="form-group form-inline">
							<label for="cc_ngaycap" class = "label_form_control">Ngày cấp:</label>
							<input type="date" class="form-control box_form_control" id="cc_ngaycap" placeholder="Ngày cấp" name="cc_ngaycap" value="${cancuoc.ngaycap}" readonly required>
						</div>
						<div class="form-group form-inline">
							<label for="cc_tinhtp" class = "label_form_control">Tỉnh:</label>
							<input type="text" class="form-control box_form_control" id="cc_tinhtp" placeholder="Tỉnh" name="cc_tinhtp" value="${diachi_cc.tinhtp}" readonly required>
						</div>
						<div class="form-group form-inline">
							<label for="cc_quanhuyen" class = "label_form_control">Quận/Huyện:</label>
							<input type="text" class="form-control box_form_control" id="cc_quanhuyen" placeholder="Quận/Huyện" name="cc_quanhuyen" value="${diachi_cc.quanhuyen}" readonly required>
						</div>
						<div class="form-group form-inline">
							<label for="cc_phuongxa" class = "label_form_control">Phường/Xã:</label>
							<input type="text" class="form-control box_form_control"id="cc_phuongxa" placeholder="Phường/Xã" name="cc_phuongxa" value="${diachi_cc.phuongxa}" readonly required>
						</div>
						<div class="form-group form-inline">
							<label for="cc_sonha" class = "label_form_control">Số nhà:</label>
							<input type="text" class="form-control box_form_control"id="cc_sonha" placeholder="Số nhà" name="cc_sonha" value="${diachi_cc.sonha}" readonly required>
						</div>
						<div class="form_button">
							<button type="button" id="btn_suacc">Sửa</button>
							<button type="submit" id="btn_luucc">Xác nhận</button>
							<button type="button" onclick="closeFormCC()" id="btn_huycc">Hủy</button>
						</div>
					</form>
				</div>
				<div class="form_add form_tacvu" id="xemdc">
					<form action="<%=request.getContextPath()%>/thaydoidiachi" class="form-container">
						<h3 class = "form_title">Địa chỉ</h3>
						<div class="form-group form-inline">
							<label for="dc_tinhtp" class = "label_form_control">Tỉnh:</label>
							<input type="text" class="form-control box_form_control" id="dc_tinhtp" placeholder="Tỉnh" name="dc_tinhtp" value="${diachi.tinhtp}" readonly required>
						</div>
						<div class="form-group form-inline">
							<label for="dc_quanhuyen" class = "label_form_control">Quận/Huyện:</label>
							<input type="text" class="form-control box_form_control" id="dc_quanhuyen" placeholder="Quận/Huyện" name="dc_quanhuyen" value="${diachi.quanhuyen}" readonly required>
						</div>
						<div class="form-group form-inline">
							<label for="dc_phuongxa" class = "label_form_control">Phường/Xã:</label>
							<input type="text" class="form-control box_form_control"id="dc_phuongxa" placeholder="Phường/Xã" name="dc_phuongxa" value="${diachi.phuongxa}" readonly required>
						</div>
						<div class="form-group form-inline">
							<label for="dc_sonha" class = "label_form_control">Số nhà:</label>
							<input type="text" class="form-control box_form_control"id="dc_sonha" placeholder="Số nhà" name="dc_sonha" value="${diachi.sonha}" readonly required>
						</div>
						<div class="form_button">
							<button type="button" id="btn_suadc">Sửa</button>
							<button type="submit" id="btn_luudc">Xác nhận</button>
							<button type="button" onclick="closeFormDC()" id="btn_huydc">Hủy</button>
						</div>
					</form>
				</div>
            </div>
        </div>
    </div>
	<script>
		let hoten = document.getElementById("hoten");
		let ngaysinh = document.getElementById("ngaysinh");
		let gioitinh = document.getElementById("gioitinh");
		let cccd = document.getElementById("cccd");
		let diachi = document.getElementById("diachi");
		let sdt = document.getElementById("sdt");
		let email = document.getElementById("email");
		let pass = document.getElementById("pass");

		let cc_cccd = document.getElementById("cc_cccd");
		let cc_ngaycap = document.getElementById("cc_ngaycap");
		let cc_tinhtp = document.getElementById("cc_tinhtp");
		let cc_quanhuyen = document.getElementById("cc_quanhuyen");
		let cc_phuongxa = document.getElementById("cc_phuongxa");
		let cc_sonha = document.getElementById("cc_sonha");

		let dc_tinhtp = document.getElementById("dc_tinhtp");
		let dc_quanhuyen = document.getElementById("dc_quanhuyen");
		let dc_phuongxa = document.getElementById("dc_phuongxa");
		let dc_sonha = document.getElementById("dc_sonha");

		let btn_suathongtin = document.getElementById("btn_suathongtin");
		let btn_doimk = document.getElementById("btn_doimk");
		let btn_save = document.getElementById("btn_save");

		let btn_suacc = document.getElementById("btn_suacc");
		let btn_huycc = document.getElementById("btn_huycc");
		let btn_luucc = document.getElementById("btn_luucc");

		let btn_suadc = document.getElementById("btn_suadc");
		let btn_luudc = document.getElementById("btn_luudc");
		let btn_huydc = document.getElementById("btn_huydc");

		let isEditing = false;

		btn_suathongtin.addEventListener("click", function() {
			if (!isEditing) {
				hoten.removeAttribute("readonly");
				ngaysinh.removeAttribute("readonly");
				gioitinh.removeAttribute("readonly");
				sdt.removeAttribute("readonly");
				email.removeAttribute("readonly");
				isEditing = true;
			} else {
				hoten.setAttribute("readonly", true);
				ngaysinh.setAttribute("readonly", true);
				gioitinh.setAttribute("readonly", true);
				sdt.setAttribute("readonly", true);
				email.setAttribute("readonly", true);
				isEditing = false;
			}
		});
		btn_save.addEventListener("click", function() {
			hoten.setAttribute("readonly", true);
			ngaysinh.setAttribute("readonly", true);
			gioitinh.setAttribute("readonly", true);
			sdt.setAttribute("readonly", true);
			pass.setAttribute("readonly", true);
		});
		btn_suacc.addEventListener("click",function (){
			moFormCCCD();
		});
		btn_huycc.addEventListener("click",function (){
			dongFormCCCD();
		});
		btn_luucc.addEventListener("click",function (){
			dongFormCCCD();
		});
		btn_suadc.addEventListener("click",function (){
			moFormDC();
		});
		btn_huydc.addEventListener("click",function (){
			dongFormDC();
		});
		btn_luudc.addEventListener("click",function (){
			dongFormDC();
		});
		function moFormCCCD(){
			cc_cccd.removeAttribute("readonly");
			cc_ngaycap.removeAttribute("readonly")
			cc_tinhtp.removeAttribute("readonly");
			cc_quanhuyen.removeAttribute("readonly");
			cc_phuongxa.removeAttribute("readonly");
			cc_sonha.removeAttribute("readonly");
		}
		function dongFormCCCD(){
			cc_cccd.setAttribute("readonly",true);
			cc_ngaycap.setAttribute("readonly",true);
			cc_tinhtp.setAttribute("readonly",true);
			cc_quanhuyen.setAttribute("readonly",true);
			cc_phuongxa.setAttribute("readonly",true);
			cc_sonha.setAttribute("readonly",true);
		}
		function moFormDC(){
			dc_tinhtp.removeAttribute("readonly");
			dc_quanhuyen.removeAttribute("readonly");
			dc_phuongxa.removeAttribute("readonly");
			dc_sonha.removeAttribute("readonly");
		}
		function dongFormDC(){
			dc_tinhtp.setAttribute("readonly",true);
			dc_quanhuyen.setAttribute("readonly",true);
			dc_phuongxa.setAttribute("readonly",true);
			dc_sonha.setAttribute("readonly",true);
		}
		function openFormCC() {
			document.getElementById("xemcc").style.display = "block";
		}
		function openFormDC() {
			document.getElementById("xemdc").style.display = "block";
		}
		function closeFormCC() {
			document.getElementById("xemcc").style.display = "none";
		}
		function closeFormDC() {
			document.getElementById("xemdc").style.display = "none";
			let diachi = document.getElementById("dc_tinhtp").value + ", " + document.getElementById("dc_quanhuyen").value + ", " +
					document.getElementById("dc_phuongxa").value + ", " + document.getElementById("dc_sonha").value;
			document.getElementById("diachi").value = diachi;
		}
	</script>
<%}%>
</body>
</html>