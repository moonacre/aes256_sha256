<?php 

defined('ACCESS') OR die('Direct access denied.');

/*
|--------------------------------------------------------------------------
| AES (Advanced Encryption Standard) Algorithm
|--------------------------------------------------------------------------
|
| Sample Usage: Registering/Logging in
|
| REGISTER A USER:
| save_to_database = AES::encrypt('yourusername','yourpassword');
|
| The code above will generate encrypted strings
| that you can save in your database. Both
| username and password will be encrypted. Hence,
| if even username is incorrect, the output will ALWAYS
| be FALSE.
|
| LOGGING IN:
| password_from_database = 'abcde1234xyz';
| where abcde1234xyz is retrieved from your database.
|
| Then decrypt:
| AES::decrypt('yourusername','yourpassword', password_from_database);
|
| As you can see, everytime you decrypt, a "key" must
| be always present. In this case, 'yourusername' is the "key".
| If even the key is wrong, then everything will be false.
| Your plain password, in this case, 'yourpassword' should
| also be present for SHA-2 layer checking.
|
| decrypt_result = 'yourpassword';
|
| Compare:
| yourpassword == decrypt_result ? true : false;
|
| If decrypt_result will match the plain password, then
| login will be successful. Otherwise, it will fail.
|
| For more information, visit AES website: https://aesencryption.net/
|
*/

class AES{

	//SHA-2 Layer
	static private $pbkdf2_hash_algorithm = 'sha256';
	static private $pbkdf2_iterations = 1000;
	static private $pbkdf2_salt_byte_size = 24;
	static private $pbkdf2_hash_byte_size = 24;
	static private $hash_sections = 4;
	static private $hash_algorithm_index = 0;
	static private $hash_iteration_index = 1;
	static private $hash_salt_index = 2;
	static private $hash_pbkdf2_index = 3;

	//AES-256 Layer
	static private $data;
	static private $key;
	static private $method = 'AES-256-CBC';
	static private $options = 0;

	static public function encrypt($key = null, $data = null){

		self::$key = $key;
		self::$data = self::generate_hash($data);


		if(self::validate_params()){
			return trim(openssl_encrypt(self::$data, self::$method, self::$key, self::$options,self::iv()));
		}else{
			throw new Exception('Invalid encryption parameters!');
		}

	}

	static public function decrypt($key = null, $plain_data = null, $data = null){

		self::$key = $key;
		self::$data = $data;

		if(self::validate_params()){
			$decrypt_data = trim(openssl_decrypt(self::$data, self::$method, self::$key, self::$options,self::iv()));
			return self::decrypt_hash($plain_data, $decrypt_data) ? true : false;
		}else{
			throw new Exception('Invalid decryption parameters!');
		} 

	}

	static private function validate_params(){
		return self::$data != null ? true : false;
	}

	static private function iv(){
		return chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
	}

	static public function generate_hash($str){

		$salt = base64_encode(mcrypt_create_iv(self::$pbkdf2_salt_byte_size, MCRYPT_DEV_URANDOM));
		return self::$pbkdf2_hash_algorithm . ':' . self::$pbkdf2_iterations . ':' .  $salt . ':' .
			base64_encode(
				self::__pbkdf2(
					self::$pbkdf2_hash_algorithm,
					$str,
					$salt,
					self::$pbkdf2_iterations,
					self::$pbkdf2_hash_byte_size,
					true
				)
			);

	}

	static public function decrypt_hash($str, $hash){

		$params = explode(':', $hash);

		if(count($params) < self::$hash_sections)
			return false;

		$pbkdf2 = base64_decode($params[self::$hash_pbkdf2_index]);

		return self::__slow_equals(
			$pbkdf2,
			self::__pbkdf2(
				$params[self::$hash_algorithm_index],
				$str,
				$params[self::$hash_salt_index],
				(int)$params[self::$hash_iteration_index],
				strlen($pbkdf2),
				true
			)
		);

	}

	static private function __slow_equals($a, $b){

		$diff = strlen($a) ^ strlen($b);

		for($i = 0; $i < strlen($a) && $i < strlen($b); $i++){
			$diff |= ord($a[$i]) ^ ord($b[$i]);
		}

		return $diff === 0;

	}

	static private function __pbkdf2($algorithm, $str, $salt, $count, $key_length, $raw_output = false){

		$algorithm = strtolower($algorithm);

		if(!in_array($algorithm, hash_algos(), true))
			trigger_error('PBKDF2 ERROR: Invalid hash algorithm.', E_USER_ERROR);
		if($count <= 0 || $key_length <= 0)
			trigger_error('PBKDF2 ERROR: Invalid parameters.', E_USER_ERROR);

		if(function_exists('hash_pbkdf2')){

			if(!$raw_output){
				$key_length = $key_length * 2;
			}

			return hash_pbkdf2($algorithm, $str, $salt, $count, $key_length, $raw_output);
		}

		$hash_length = strlen(hash($algorithm, '', true));
		$block_count = ceil($key_length / $hash_length);

		$output = '';

		for($i = 1; $i <= $block_count; $i++) {

			$last = $salt . pack('N', $i);

			$last = $xorsum = hash_hmac($algorithm, $last, $str, true);

			for ($j = 1; $j < $count; $j++) {
				$xorsum ^= ($last = hash_hmac($algorithm, $last, $str, true));
			}

			$output .= $xorsum;

		}

		return $raw_output ? substr($output, 0, $key_length) : bin2hex(substr($output, 0, $key_length));

	}


}