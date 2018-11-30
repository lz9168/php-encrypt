<?php
// crypt3des
/**
 * Created by PhpStorm.
 * User: KeenSting
 * Date: 2017/11/23
 * Time: ����2:28
 * Name: ��С��
 * Phone: 13126734215
 * QQ: 707719848
 * File Description: 3DES_ECB_PKCS5Padding
 */

class TripleDesEcb{

    /**����
     * @param $text string �ı�����
     * @param $key string ��Կ max 24
     * @return string
     */
    public function encrypt($text,$key)
    {

        $iv   = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_TRIPLEDES,MCRYPT_MODE_ECB), MCRYPT_RAND);
        $text = $this->pkcs5Pad($text);
        $td = mcrypt_module_open(MCRYPT_3DES,'',MCRYPT_MODE_ECB,'');
        mcrypt_generic_init($td,$key,$iv);
        $data = base64_encode(mcrypt_generic($td, $text));
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        print_r($data);
        return $data;

    }

    /**����
     * @param $text
     * @param $key
     */
    public function decrypt($text,$key)
    {
        $iv   = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_TRIPLEDES,MCRYPT_MODE_ECB), MCRYPT_RAND);
        $td = mcrypt_module_open(MCRYPT_3DES, '', MCRYPT_MODE_ECB, '');
        mcrypt_generic_init($td, $key, $iv);
        $data  = $this->pkcs5UnPad(mdecrypt_generic($td, base64_decode($text)));
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        print_r($data);
    }

    /**
     * @param $text
     * @return string
     */
    private function pkcs5Pad($text)
    {
        $pad = 8 - (strlen($text) % 8);
        return $text . str_repeat(chr($pad), $pad);
    }

    /**
     * @param $text
     * @return bool|string
     */
    private function pkcs5UnPad($text)
    {
        $pad = ord($text{strlen($text)-1});
        if ($pad > strlen($text)) return false;
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) return false;
        return substr($text, 0, -1 * $pad);
    }
}

//test
$a = new TripleDesEcb();
$r = $a->encrypt('keensting','AA190CD754A89EF100190CD754A89EF1');
$a->decrypt($r,'AA190CD754A89EF100190CD754A89EF1');

//���Եļ��ܽ������base64�����Ϊ��juyYkxc6B+Ym3p8QQdvXIg==�����ܼ��ɵõ�ԭ�ģ��ԳƼ����㷨�ļ��ܺͽ����õ���ͬһ���ࣩ
?>

