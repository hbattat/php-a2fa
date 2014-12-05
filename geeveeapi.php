<?php
/*  GeeVeeSMS 1.0
 *  Allows you to send SMS to any US/Canada phone number using your google voice account
 *
 *  Author: Sam Battat hbattat@msn.com
 *          http://github.com/hbattat
 *
 *  License: This code is released under the MIT Open Source License. (Feel free to do whatever)
 *
 *  Last update: Feb 03 2014
*/

class GeeVeeSMS {
	public $email_address;
	public $password;
	private $init_url = 'https://www.google.com/voice';
	private $refer_url = 'https://www.google.com/voice';
	private $login_url = 'https://accounts.google.com/ServiceLoginAuth';
	private $gv_url = 'https://www.google.com/voice/m';
	private $sms_url = 'https://www.google.com/voice/m/sms';
	private $send_url = 'https://www.google.com/voice/m/sendsms';
	private $call_url = 'https://www.google.com/voice/m/callsms';
	private $send_call = 'https://www.google.com/voice/m/sendcall';
	private $verify_url = 'https://accounts.google.com/LoginVerification';
	private $token;
	private $cookies_file;

	private function getToken(){
		$page = $this->curlGet($this->sms_url);
                $fields = $this->getFormFields($page);
		return $fields['_rnr_se'];
	}

	public function __construct($email_address, $password){
		$this->email_address = $email_address;
		$this->password = $password;
		$this->cookies_file = tempnam(sys_get_temp_dir(), 'GeeVee-cookies');

		//login
		$this->gvLogin();
		$this->token = $this->getToken();
	}

	public function call($phone, $from){
		//set fields
                $fields['_rnr_se'] = $this->token;
                $fields['number'] = $phone;
                $fields['phone'] = $from;

                $post_string = '';
                foreach($fields as $key => $value) {
                        $post_string .= $key . '=' . urlencode($value) . '&';
                }
                $post_string = substr($post_string, 0, -1);

                //send the sms
                $this->refer_url = $this->call_url;
                $send_call = $this->curlPost($this->send_call, $post_string, $this->refer_url);
	}

	public function sendSMS($phone, $message){
		//get/set the fields
		$fields['_rnr_se'] = $this->token;
		$fields['number'] = $phone;
		$fields['smstext'] = $message;

		$post_string = '';
		foreach($fields as $key => $value) {
    			$post_string .= $key . '=' . urlencode($value) . '&';
		}
		$post_string = substr($post_string, 0, -1);

		//send the sms
		$this->refer_url = $this->sms_url;
		$send_sms = $this->curlPost($this->send_url, $post_string, $this->refer_url);
	}

	private function gvLogin(){	
		//request the homepage of google voice
		$init_login = $this->curlGet($this->init_url);

		//get/set login fields
		$fields = $this->getFormFields($init_login, true);
		$fields['Email'] = $this->email_address;
		$fields['Passwd'] = $this->password;
		//$fields['_utf8'] = '%E2%98%83';
		$post_string = '';
		foreach($fields as $key => $value) {
    			$post_string .= $key . '=' . urlencode($value) . '&';
		}
		$post_string = substr($post_string, 0, -1);

		//do login
		$curl_login = $this->curlPost($this->login_url, $post_string, $this->refer_url);

		return $curl_login;
	}

	private function curlGet($url){
        	$ch = curl_init();
        	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        	curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_0 like Mac OS X; en-us) AppleWebKit/532.9 (KHTML, like Gecko) Version/4.0.5 Mobile/8A293 Safari/6531.22.7');
        	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
        	curl_setopt($ch, CURLOPT_COOKIEJAR, $this->cookies_file);
        	curl_setopt($ch, CURLOPT_COOKIEFILE, $this->cookies_file);
        	curl_setopt($ch, CURLOPT_HEADER, 0);
        	curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
        	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 120);
       		curl_setopt($ch, CURLOPT_TIMEOUT, 120);
        	curl_setopt($ch, CURLOPT_URL, $url);
        	$data = curl_exec($ch);
        	curl_close($ch);
        	return $data;
	}

	private function curlPost($url, $fields_str, $referer = null){
	 	$ch = curl_init();
        	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        	curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_0 like Mac OS X; en-us) AppleWebKit/532.9 (KHTML, like Gecko) Version/4.0.5 Mobile/8A293 Safari/6531.22.7');
        	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
        	curl_setopt($ch, CURLOPT_COOKIEJAR, $this->cookies_file);
        	curl_setopt($ch, CURLOPT_COOKIEFILE, $this->cookies_file);
        	curl_setopt($ch, CURLOPT_HEADER, 0);
        	curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
        	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 120);
        	curl_setopt($ch, CURLOPT_TIMEOUT, 120);
        	if(!empty($referer)){
                	curl_setopt($ch, CURLOPT_REFERER, $referer);
        	}
        	curl_setopt($ch, CURLOPT_POST, true);
        	curl_setopt($ch, CURLOPT_POST, "application/x-www-form-urlencoded");
        	curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_str);
        	curl_setopt($ch, CURLOPT_URL, $url);
        	$data = curl_exec($ch);
        	return $data;
	} 
	
	private function getFormFields($data, $is_login_form = false){
        	if($is_login_form){
                	if (preg_match('/(<form.*?<\/form>)/is', $data, $matches)) {
                        	$inputs = $this->getInputs($matches[1]);
                        	return $inputs;
                	}
			else {
                        	die('Error: could not find login form');
                	}
        	}
        	else{
                	if (preg_match('/(<form.*?<\/form>)/is', $data, $matches)) {
                        	$inputs = $this->getInputs($matches[1]);
                        	return $inputs;
                	}
			else{
                        	die('Error: could not find any form');
                	}
        	}
	}

	private function getInputs($form){
    		$inputs = array();
    		$elements = preg_match_all('/(<input[^>]+>)/is', $form, $matches);
    		if ($elements > 0) {
        		for($i = 0; $i < $elements; $i++) {
            			$el = preg_replace('/\s{2,}/', ' ', $matches[1][$i]);
            			if (preg_match('/name=(?:["\'])?([^"\'\s]*)/i', $el, $name)) {
                			$name  = $name[1];
                			$value = '';
                			if (preg_match('/value=(?:["\'])?([^"\'\s]*)/i', $el, $value)) {
                    				$value = $value[1];
                			}
                			$inputs[$name] = $value;
            			}
        		}
    		}
    		return $inputs;
	}
}
