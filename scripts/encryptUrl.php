<?php

if ($argc < 5)
{
	die("Usage:\n\tphp encryptUrl.php <base url> <encrypted part> <encryption key> <encryption iv>\n");
}

$BASE_URL = $argv[1];
$ENC_URL = $argv[2];
$ENC_KEY = pack("H*", $argv[3]);
$ENC_IV = pack("H*", $argv[4]);

$HASH_SIZE = 8;

// add signature
$signedUrl = substr(md5($ENC_URL, true), 0, $HASH_SIZE) . $ENC_URL;

// add PKCS#7 padding
$pad = 16 - (strlen($signedUrl) % 16);
$signedUrl .= str_repeat(chr($pad), $pad);

// AES encrypt
$encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $ENC_KEY, $signedUrl, MCRYPT_MODE_CBC, $ENC_IV);

// base64 encrypt
$base64Encoded = rtrim(strtr(base64_encode($encrypted), '+/', '-_'), '=');

echo $BASE_URL . $base64Encoded . "\n";
