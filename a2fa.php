<?php
/**
 * PHP Class for creating two factor authentication secret
 * and verifying the one-time code
 * and create a QR code to use with apps such as Google Authenticator
 */
class a2fa {
	private $code_length = 6;
	private $gv_username;
	private $gv_password;


	public function setGV($username, $password)
	{
		$this->gv_username = $username;
		$this->gv_password = $password;
	}

	public function generateSecret($length = 16)
	{
		$chars = $this->getBase32Chars();
		$secret = '';
		$random = openssl_random_pseudo_bytes($length);
		for ($i = 0; $i < $length; $i++){
			$secret .= $chars[ord($random[$i]) & 31];
		}
		return $secret;
	}

	public function generateQR($secret, $name = 'PHP A2FA')
	{
		$text = 'otpauth://totp/'.urlencode($name).'?secret='.urlencode($secret);
		$url = 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl='.$text;
		$data = file_get_contents($url);
		$base64= base64_encode($data);
		$img = 'data:image/png;base64,'.$base64;
		return $img;
	}


	public function sendCodeSMS($secret, $phone){
		if(!empty($this->gv_username) && !empty($this->gv_password)){
			require_once 'geeveeapi.php';
			$code = $this->calcCode($secret);
			$msg = 'Your one time code is: '.$code;
			$gv = new GeeVeeSMS($this->gv_username, $this->gv_password);
			$gv->sendSMS($phone, $msg);
			return true;
		}
		else{
			return false;
		}
	}
	
	public function verifyCode($secret, $code, $time_window = 1)
	{
		$current_time_window = floor(time() / 30);
		for ($i = -$time_window; $i <= $time_window; $i++) {
			$code_from_secret = $this->calcCode($secret, $current_time_window + ($i * 30));
			if ($code_from_secret == $code ) {
				return true;
			}
		}
		return false;
	}


	private function getBase32Chars()
	{
		return array(
				'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
				'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
				'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
				'Y', 'Z', '2', '3', '4', '5', '6', '7',
				'='
			    );
	}

	private function calcCode($secret, $timeSlice = null)
	{
		if ($timeSlice === null) {
			$timeSlice = floor(time() / 30);
		}
		$secretkey = $this->decodeBase32($secret);
		$time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);
		$hm = hash_hmac('SHA1', $time, $secretkey, true);
		$offset = ord(substr($hm, -1)) & 0x0F;
		$hashpart = substr($hm, $offset, 4);
		$value = unpack('N', $hashpart);
		$value = $value[1];
		$value = $value & 0x7FFFFFFF;
		$modulo = pow(10, $this->code_length);
		return str_pad($value % $modulo, $this->code_length, '0', STR_PAD_LEFT);
	}


	private function decodeBase32($str)
	{
		$chars = $this->getBase32Chars();
		$tmp = '';

		foreach (str_split($str) as $c){
			if (false === ($v = array_search($c, $chars))){
				$v = 0;
			}
			$tmp .= sprintf('%05b', $v);
		}
		$args = array_map('bindec', str_split($tmp, 8));
		array_unshift($args, 'C*');

		return rtrim(call_user_func_array('pack', $args), "\0");
	}
}
