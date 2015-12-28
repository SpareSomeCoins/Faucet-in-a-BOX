<?php

class SpareSomeCoins
{
    protected $api_key;
    protected $currency;
    public $last_status = null;
    protected $api_base = "https://api.sparesomecoins.com/v1.0/";

    public function __construct($api_key, $currency, $disable_curl = false, $verify_peer = true) {
        $this->api_key = $api_key;
        $this->currency = $currency;
        $this->disable_curl = $disable_curl;
        $this->verify_peer = $verify_peer;
        $this->curl_warning = false;
    } 

    public function __CURL($method, $params = array()) {
        $params = array_merge($params, array("api_key" => $this->api_key, "currency" => $this->currency));
        $ch = curl_init($this->api_base . $method . '/');
        curl_setopt($ch, CURLOPT_POST, true); 
        curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);  
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_CAINFO, getcwd() . "/libs/cacert.pem");
        $response = curl_exec($ch);
        curl_close($ch);

        return $response; 
    } 

    public function send($to, $amount, $referral = "") {
        $r = $this->__CURL("send", array("to" => $to, "amount" => $amount, "referral" => $referral));
        $response = json_decode($r, true);

			if (array_key_exists("status", $response) && $response["status"] == 200) {
				return array(
					'success' => true,
					'message' => 'Payment sent to your address using SpareSomeCoins.com',
					'html' => '<div class="alert alert-success">' . htmlspecialchars($amount) . ' satoshi was sent to <a target="_blank" href="https://sparesomecoins.com/check/' . rawurlencode($to) . '">your SpareSomeCoins.com address</a>.</div>',
					'html_coin' => '<div class="alert alert-success">' . htmlspecialchars(rtrim(rtrim(sprintf("%.8f", $amount/100000000), '0'), '.')) . ' '.$this->currency.' was sent to <a target="_blank" href="https://sparesomecoins.com/check/' . rawurlencode($to) . '">your SpareSomeCoins.com address</a>.</div>',
					'balance' => $response["balance"],
					'balance_bitcoin' => $response["balance_bitcoin"],
					'response' => json_encode($response)
				);
			} else {
				return array(
					'success' => false,
					'message' => $response["message"],
					'html' => htmlspecialchars($response["message"]), 
					'timer' => $response['timer'],
					'response' => json_encode($response)
				);
			}
		
    }

    public function sendReferralEarnings($to, $amount) {
        return $this->send($to, $amount, "true");
    }

    public function getBalance() {
        $r = $this->__CURL("balance");
		$response = json_decode($r, true);
		return $response;
    }	

    public function getCurrencies() {
        $r = $this->__CURL("currencies");
		$response = json_decode($r, true);
		return $response;		
	}
    public function fiabVersionCheck() {return true;}


}
