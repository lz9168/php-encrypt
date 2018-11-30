<?php
// 利用php的mcrypt模块加密解密(AES、DES等等)

// des加密

$cipher_list = mcrypt_list_algorithms();//mcrypt支持的加密算法列表
$mode_list = mcrypt_list_modes();//mcrypt支持的加密模式列表

// print_r($cipher_list);
// print_r($mode_list);

function encrypt($key,$data){
    $td = mcrypt_module_open("des", "", "ecb", "");//使用MCRYPT_DES算法,ecb模式
    $size = mcrypt_enc_get_iv_size($td);       //设置初始向量的大小
    $iv = mcrypt_create_iv($size,MCRYPT_RAND); //创建初始向量

    $key_size = mcrypt_enc_get_key_size($td);       //返回所支持的最大的密钥长度（以字节计算）
    $salt = '';
    $subkey = substr(md5(md5($key).$salt), 0,$key_size);//对key复杂处理，并设置长度

    mcrypt_generic_init($td, $subkey, $iv);
    $endata = mcrypt_generic($td, $data);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return $endata;
}

function decrypt($key,$endata){
    $td = mcrypt_module_open("des", "", "ecb", "");//使用MCRYPT_DES算法,ecb模式
    $size = mcrypt_enc_get_iv_size($td);       //设置初始向量的大小
    $iv = mcrypt_create_iv($size,MCRYPT_RAND); //创建初始向量
    $key_size = mcrypt_enc_get_key_size($td);       //返回所支持的最大的密钥长度（以字节计算）
    $salt = '';
    $subkey = substr(md5(md5($key).$salt), 0,$key_size);//对key复杂处理，并设置长度
    mcrypt_generic_init($td, $subkey, $iv);
    $data = rtrim(mdecrypt_generic($td, $endata)).'\n';
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return $data;
}


$key = "www.tencent.com";
// $data = "返回所支持的最大的密钥长度（涉及到发件费啦";
$data = "dadfafdafd,我是一个好孩子";

$endata =  encrypt($key,$data);

$data1 = decrypt($key,$endata);

echo $endata; //直接输出，在网页上是乱码，用base64_encode处理，就变成由字符、数组、加号、斜杠等共64种字符注册
echo base64_encode($endata);
echo $data1;

/*
//rijndael-128，rijndael-192，rijndael-256就是AES加密，3种分别是使用不同的数据块和密钥长度进行加密。
Array
(
    [0] => cast-128
    [1] => gost
    [2] => rijndael-128  
    [3] => twofish
    [4] => arcfour
    [5] => cast-256
    [6] => loki97
    [7] => rijndael-192
    [8] => saferplus
    [9] => wake
    [10] => blowfish-compat
    [11] => des
    [12] => rijndael-256
    [13] => serpent
    [14] => xtea
    [15] => blowfish
    [16] => enigma
    [17] => rc2
    [18] => tripledes
)
Array
(
    [0] => cbc
    [1] => cfb
    [2] => ctr
    [3] => ecb
    [4] => ncfb
    [5] => nofb
    [6] => ofb
    [7] => stream
)
*/

// 一般情况，用上面代码块即可，如果要求自己创造一个类，可以使用下面的类：

/*
 * 类中，功能部分功能没有提炼，还需进一步修改
*/
class Mymcrypt {

    public $key = "www.tence.com"; //必须是字符串了，如果是数字

    // 加密
    public function do_mencrypt($input)
    {
        // $key = substr(md5($this->key), 0, 24);
        // $td = mcrypt_module_open('des', '', 'ecb', '');
        // $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        $td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_ECB, '');
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);

        //没有做key size设定
        $key_size = mcrypt_enc_get_key_size($td);       //返回所支持的最大的密钥长度（以字节计算）
        $salt = '';
        $subkey = substr(md5(md5($this->key).$salt), 0,$key_size);//对key复杂处理，并设置长度

        mcrypt_generic_init($td, $subkey, $iv);
        $encrypted_data = mcrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        // return trim(chop($this->base64url_encode($encrypted_data)));
        return $encrypted_data;
    }

    // 解密
    //$input - stuff to decrypt
    public function do_mdecrypt($input)
    {
        // $key = substr(md5($this->key), 0, 24);
        // $td = mcrypt_module_open('des', '', 'ecb', '');
        // $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        $td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_ECB, '');
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);

        //没有做key size设定
        $key_size = mcrypt_enc_get_key_size($td); //返回支持的最大的密钥长度（以字节计）也可自己设定比如24
        $salt = '';
        $subkey = substr(md5(md5($this->key).$salt), 0,$key_size);////对key复杂处理，并设置长度

        mcrypt_generic_init($td, $subkey, $iv);
        $decrypted_data = mdecrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        // return trim(chop($decrypted_data));
        return $decrypted_data;
    }

    // base64在url传递过程中需要注意的
    // 把base64加密后在url传输，会把“+“，”/”分别替换为”-”，”_”，以及会把末尾的等号“=”去掉。
    // 另外base64加密后的长度必然是4的倍数，所以可以根据这个还原“=”号
    function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        // return $data;  //不处理会乱码
        // return base64_encode($data);
    }

    function base64url_decode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

} 

// 用法
$myMcrypt = new Mymcrypt();
$data = 'PD867H4V9J6B';
$value = $myMcrypt->do_mencrypt($data);
// $value = $myMcrypt->base64url_encode($value); //可以使用特殊处理过的base64_encode

$value = base64_encode($value); //方便在网页显示
$value = trim($value);          //有时后面会带很多预定于字符串
echo "$value <br/> 长度：".strlen($value)."<br/>";

$value = base64_decode($value); //解码后解密
$value = $myMcrypt->do_mdecrypt($value);
$value = trim($value);
echo "$value <br/>长度：".strlen($value)."<br/>";

?>