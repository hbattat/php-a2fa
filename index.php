<?php
error_reporting(E_ALL);
ini_set('dispaly_errors', 1);

include 'a2fa.php';

$a2fa = new a2fa();
$a2fa->setGV('email', 'pass');

$base32 = $a2fa->generateSecret();
//echo "$base32<br />";

//echo $a2fa->verifyCode('YXWP3VMDAWTVNSHT', '644900');

echo '<img src="'.$a2fa->generateQR('YXWP3VMDAWTVNSHT').'"/>';

echo $a2fa->sendCodeSMS('YXWP3VMDAWTVNSHT', '3374990343');
?>
