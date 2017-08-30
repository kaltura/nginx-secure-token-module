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

$encrypted = null;

// AES encrypt
if (function_exists('mcrypt_encrypt')) 
{
    $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $ENC_KEY, $signedUrl, MCRYPT_MODE_CBC, $ENC_IV);
}
else if (function_exists('openssl_encrypt'))
{
    $encrypted = openssl_encrypt($signedUrl, 'aes-256-cbc', $ENC_KEY, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $ENC_IV);
}
else
{
    die("need either mcrypt or openssl extension\n");
}

// base64 encrypt
$base64Encoded = rtrim(strtr(base64_encode($encrypted), '+/', '-_'), '=');

echo $BASE_URL . $base64Encoded . "\n";
