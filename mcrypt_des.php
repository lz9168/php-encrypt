<?php
// ����php��mcryptģ����ܽ���(AES��DES�ȵ�)

// des����

$cipher_list = mcrypt_list_algorithms();//mcrypt֧�ֵļ����㷨�б�
$mode_list = mcrypt_list_modes();//mcrypt֧�ֵļ���ģʽ�б�

// print_r($cipher_list);
// print_r($mode_list);

function encrypt($key,$data){
    $td = mcrypt_module_open("des", "", "ecb", "");//ʹ��MCRYPT_DES�㷨,ecbģʽ
    $size = mcrypt_enc_get_iv_size($td);       //���ó�ʼ�����Ĵ�С
    $iv = mcrypt_create_iv($size,MCRYPT_RAND); //������ʼ����

    $key_size = mcrypt_enc_get_key_size($td);       //������֧�ֵ�������Կ���ȣ����ֽڼ��㣩
    $salt = '';
    $subkey = substr(md5(md5($key).$salt), 0,$key_size);//��key���Ӵ��������ó���

    mcrypt_generic_init($td, $subkey, $iv);
    $endata = mcrypt_generic($td, $data);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return $endata;
}

function decrypt($key,$endata){
    $td = mcrypt_module_open("des", "", "ecb", "");//ʹ��MCRYPT_DES�㷨,ecbģʽ
    $size = mcrypt_enc_get_iv_size($td);       //���ó�ʼ�����Ĵ�С
    $iv = mcrypt_create_iv($size,MCRYPT_RAND); //������ʼ����
    $key_size = mcrypt_enc_get_key_size($td);       //������֧�ֵ�������Կ���ȣ����ֽڼ��㣩
    $salt = '';
    $subkey = substr(md5(md5($key).$salt), 0,$key_size);//��key���Ӵ��������ó���
    mcrypt_generic_init($td, $subkey, $iv);
    $data = rtrim(mdecrypt_generic($td, $endata)).'\n';
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return $data;
}


$key = "www.tencent.com";
// $data = "������֧�ֵ�������Կ���ȣ��漰����������";
$data = "dadfafdafd,����һ���ú���";

$endata =  encrypt($key,$data);

$data1 = decrypt($key,$endata);

echo $endata; //ֱ�����������ҳ�������룬��base64_encode�����ͱ�����ַ������顢�Ӻš�б�ܵȹ�64���ַ�ע��
echo base64_encode($endata);
echo $data1;

/*
//rijndael-128��rijndael-192��rijndael-256����AES���ܣ�3�ֱַ���ʹ�ò�ͬ�����ݿ����Կ���Ƚ��м��ܡ�
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

// һ����������������鼴�ɣ����Ҫ���Լ�����һ���࣬����ʹ��������ࣺ

/*
 * ���У����ܲ��ֹ���û�������������һ���޸�
*/
class Mymcrypt {

    public $key = "www.tence.com"; //�������ַ����ˣ����������

    // ����
    public function do_mencrypt($input)
    {
        // $key = substr(md5($this->key), 0, 24);
        // $td = mcrypt_module_open('des', '', 'ecb', '');
        // $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        $td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_ECB, '');
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);

        //û����key size�趨
        $key_size = mcrypt_enc_get_key_size($td);       //������֧�ֵ�������Կ���ȣ����ֽڼ��㣩
        $salt = '';
        $subkey = substr(md5(md5($this->key).$salt), 0,$key_size);//��key���Ӵ��������ó���

        mcrypt_generic_init($td, $subkey, $iv);
        $encrypted_data = mcrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        // return trim(chop($this->base64url_encode($encrypted_data)));
        return $encrypted_data;
    }

    // ����
    //$input - stuff to decrypt
    public function do_mdecrypt($input)
    {
        // $key = substr(md5($this->key), 0, 24);
        // $td = mcrypt_module_open('des', '', 'ecb', '');
        // $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        $td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_ECB, '');
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);

        //û����key size�趨
        $key_size = mcrypt_enc_get_key_size($td); //����֧�ֵ�������Կ���ȣ����ֽڼƣ�Ҳ���Լ��趨����24
        $salt = '';
        $subkey = substr(md5(md5($this->key).$salt), 0,$key_size);////��key���Ӵ��������ó���

        mcrypt_generic_init($td, $subkey, $iv);
        $decrypted_data = mdecrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        // return trim(chop($decrypted_data));
        return $decrypted_data;
    }

    // base64��url���ݹ�������Ҫע���
    // ��base64���ܺ���url���䣬��ѡ�+������/���ֱ��滻Ϊ��-������_�����Լ����ĩβ�ĵȺš�=��ȥ����
    // ����base64���ܺ�ĳ��ȱ�Ȼ��4�ı��������Կ��Ը��������ԭ��=����
    function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        // return $data;  //�����������
        // return base64_encode($data);
    }

    function base64url_decode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

} 

// �÷�
$myMcrypt = new Mymcrypt();
$data = 'PD867H4V9J6B';
$value = $myMcrypt->do_mencrypt($data);
// $value = $myMcrypt->base64url_encode($value); //����ʹ�����⴦�����base64_encode

$value = base64_encode($value); //��������ҳ��ʾ
$value = trim($value);          //��ʱ�������ܶ�Ԥ�����ַ���
echo "$value <br/> ���ȣ�".strlen($value)."<br/>";

$value = base64_decode($value); //��������
$value = $myMcrypt->do_mdecrypt($value);
$value = trim($value);
echo "$value <br/>���ȣ�".strlen($value)."<br/>";

?>