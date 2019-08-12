<?php
/**
 * Created by PhpStorm.
 * User: pizepei
 * Date: 2019/8/2
 * Time: 15:20
 * @title 微信sdk
 */

namespace pizepei\wechatClient;


use pizepei\encryption\aes\Prpcrypt;
use pizepei\encryption\SHA1;
use pizepei\helper\Helper;

class Client
{
    /**
     * 配置
     * @var array
     */
    protected $config = [

    ];

    /**
     * Client constructor.
     * @param array $config
     */
    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function getQr($code,string $type,int $terrace=60)
    {
        # 准备数据
        $data = [
            'code'=>$code,
            'type'=>$type,
            'terrace'=>$terrace,
        ];
        # 加密数据
        $Prpcrypt = new Prpcrypt($this->config['encoding_aes_key']);
        $ciphertext = $Prpcrypt->encrypt(Helper::init()->json_encode($data),$this->config['appid']);
        $sha1 = new  SHA1();
        $signature = $sha1->setSignature($this->config['token'],$ciphertext);
        if (!$signature) throw new \Exception('加密错误');
        # 请求接口获取
        $res = Helper::init()->httpRequest($this->config['url'],Helper::init()->json_encode($signature));
        if ($res['RequestInfo']['http_code'] !==200) throw new \Exception('请求错误');

        $body = Helper::init()->json_decode($res['body']);
        if (!$body)throw new \Exception('响应数据错误'.$res['body']);
        # 解密数据
        if (!$sha1->verifySignature($this->config['token'],$body)) throw new \Exception('签名错误');
        $data = $Prpcrypt->decrypt($body['encrypt_msg']);
        if (Helper::init()->is_empty($data[1])){
            throw new \Exception('响应data数据错误');
        }
        $data = Helper::init()->json_decode($data[1]);
        if (Helper::init()->is_empty($data,'url')){
            throw new \Exception('响应url数据错误');
        }
        # 获取 jwt
        $wjt = [
            'data'=>
                [
                    'uid'   =>   $data['id'],
                    'appid' =>   $data['appid'],
                    'type'  => $data['type'],
                ]
        ];
        $Client = new \pizepei\service\websocket\Client($wjt);
        $data['jwt_url'] = 'ws://'.$Client::host.':'.$Client::port.$Client->JWT_param;
        return $data;
    }

    public function codeAppVerify(array$body,string$id,$code,string $openid,string$ip='')
    {

        $Prpcrypt = new Prpcrypt($this->config['encoding_aes_key']);
        $sha1 = new  SHA1();
        if (!$sha1->verifySignature($this->config['token'],$body)) throw new \Exception('签名错误');
        # 解密
        $data = $Prpcrypt->decrypt($body['encrypt_msg']);
        if (Helper::init()->is_empty($data[1])){
            throw new \Exception('数据错误');
        }
        $data = Helper::init()->json_decode($data[1]);
        if (Helper::init()->is_empty($data)){throw new \Exception('数据错误!');}
        if ($id !== $data['id']) {throw new \Exception('非法的二维码数据');}
        if ($code !==$data['code']) {throw new \Exception('非法的code');}
        if ($openid !==$data['openid']) {throw new \Exception('非法的微信信息');}


    }
}