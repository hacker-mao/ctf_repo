<html>
<head>
</head>
<body bgcolor="#000000">
<font size="3" color="#FFFF00">
<div align="right">
<a style="font-size:.8em;color:#FFFF00" href='index.php'><img src="../images/Home.png" height='45'; width='45'></br>HOME</a>
</div>
<?PHP ob_start(); ?>
<?PHP
session_start();
//including the Mysql connect parameters.
include("../sql-connections/sql-connect.php");
function sqllogin($con){
   $username = mysqli_real_escape_string($con, $_POST["login_user"]);
   $password = mysqli_real_escape_string($con, $_POST["login_password"]);
   $sql = "SELECT * FROM users WHERE username='$username' and password='$password'";
//$sql = "SELECT COUNT(*) FROM users WHERE username='$username' and password='$password'";


   $res = mysqli_query($con, $sql) or die('You tried to be real smart, Try harder!!!! :( ');


   $row = mysqli_fetch_row($res);
   //print_r($row) ;
   if ($row[1]) {
         return $row[1];
   } else {
            return 0;
   }
}
$login = sqllogin($con);
if (!$login== 0) 
{  

   $_SESSION["username"] = $login;
   setcookie("Auth", 1, time()+3600);  /* expire in 15 Minutes */

   header('Location: logged-in.php');
   ob_end_flush(); 


} 
else
{
?>
<tr><td colspan="2" style="text-align:center;"><br/><p style="color:#FF0000;">
<center>
<img src="../images/slap1.jpg">
</center>
</p></td></tr>
<?PHP
} 
?>






</body>
</html>